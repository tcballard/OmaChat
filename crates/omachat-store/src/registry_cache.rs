use crate::{SealedStore, StoreError};
use omachat_crypto::{AccountId, GlobalHandle};
use omachat_registry::{
    AcceptedRegistryRecord, HandleClaimSnapshot, RegistryError, RegistryReceipt,
};
use serde::{Deserialize, Serialize};
use std::{collections::BTreeMap, error::Error, fmt, io::Cursor};
use zeroize::Zeroizing;

const REGISTRY_CACHE_RECORD: &str = "registry-cache-v1";
const REGISTRY_CACHE_VERSION: u16 = 1;
const MAX_REGISTRY_CACHE_ENTRIES: usize = 4_096;
const MAX_REGISTRY_CACHE_PLAINTEXT_BYTES: usize = 4 * 1024 * 1024;

/// Exact registry evidence retained after successful signature and claim checks.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CachedRegistryRecord {
    pub record: AcceptedRegistryRecord,
    pub verified_at: u64,
}

/// Truthful local availability state for previously verified registry evidence.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum RegistryCacheLookup {
    Missing,
    Fresh(CachedRegistryRecord),
    OfflineStale(CachedRegistryRecord),
    UnusableClockRollback(CachedRegistryRecord),
}

impl RegistryCacheLookup {
    #[must_use]
    pub const fn record(&self) -> Option<&CachedRegistryRecord> {
        match self {
            Self::Missing => None,
            Self::Fresh(record)
            | Self::OfflineStale(record)
            | Self::UnusableClockRollback(record) => Some(record),
        }
    }
}

/// Bounded sealed cache of independently verified registry claim evidence.
///
/// The cache retains every observed receipt rather than only an account's latest
/// state. That preserves chain evidence across restart and prevents a stale
/// signed receipt from being refreshed after a newer account revision was seen.
#[derive(Clone, Debug)]
pub struct VerifiedRegistryCache {
    pinned_registry_key: [u8; 32],
    records_by_sequence: BTreeMap<u64, CachedRegistryRecord>,
    latest_sequence_by_account: BTreeMap<AccountId, u64>,
}

impl VerifiedRegistryCache {
    /// Load and fully revalidate the sealed cache, or create an empty cache that
    /// immediately persists the supplied registry-key pin.
    pub fn load_or_create(
        store: &SealedStore,
        pinned_registry_key: [u8; 32],
    ) -> Result<Self, RegistryCacheError> {
        match store.read(REGISTRY_CACHE_RECORD) {
            Ok(bytes) => {
                let bytes = Zeroizing::new(bytes);
                let snapshot: RegistryCacheSnapshot =
                    serde_json::from_slice(&bytes).map_err(|_| RegistryCacheError::Encoding)?;
                Self::restore(snapshot, pinned_registry_key)
            }
            Err(StoreError::RecordNotFound) => {
                let cache = Self::empty(pinned_registry_key);
                Self::persist(store, &cache)?;
                Ok(cache)
            }
            Err(error) => Err(RegistryCacheError::Store(error)),
        }
    }

    /// Record evidence returned by an authoritative adapter only after its exact
    /// signed claim has been verified against the pinned registry key.
    ///
    /// Persistence completes before the in-memory cache advances.
    pub fn observe(
        &mut self,
        store: &SealedStore,
        record: AcceptedRegistryRecord,
        verified_at: u64,
    ) -> Result<(), RegistryCacheError> {
        let mut candidate = self.clone();
        candidate.apply_observation(record, verified_at)?;
        Self::persist(store, &candidate)?;
        *self = candidate;
        Ok(())
    }

    #[must_use]
    pub const fn pinned_registry_key(&self) -> &[u8; 32] {
        &self.pinned_registry_key
    }

    #[must_use]
    pub fn len(&self) -> usize {
        self.records_by_sequence.len()
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.records_by_sequence.is_empty()
    }

    #[must_use]
    pub fn lookup_account(
        &self,
        account_id: &AccountId,
        now: u64,
        max_age_seconds: u64,
    ) -> RegistryCacheLookup {
        self.latest_for_account(account_id)
            .map_or(RegistryCacheLookup::Missing, |record| {
                classify(record, now, max_age_seconds)
            })
    }

    #[must_use]
    pub fn lookup_handle(
        &self,
        handle: &GlobalHandle,
        now: u64,
        max_age_seconds: u64,
    ) -> RegistryCacheLookup {
        self.latest_records()
            .find(|record| record.record.receipt.handle.as_global_handle() == handle)
            .map_or(RegistryCacheLookup::Missing, |record| {
                classify(record, now, max_age_seconds)
            })
    }

    /// Resolve only a currently cached account-root assertion for this Nostr
    /// key. V1 handle claims do not include a Schnorr proof of private-key
    /// control, so callers must not present this association as a verified
    /// Nostr principal binding. Historical device keys remain audit evidence
    /// but are not presented as the account's current asserted key after a
    /// newer binding is observed.
    #[must_use]
    pub fn lookup_nostr_public_key(
        &self,
        public_key: &[u8; 32],
        now: u64,
        max_age_seconds: u64,
    ) -> RegistryCacheLookup {
        self.latest_records()
            .find(|record| {
                &record.record.claim.binding().device_keys.nostr_public_key == public_key
            })
            .map_or(RegistryCacheLookup::Missing, |record| {
                classify(record, now, max_age_seconds)
            })
    }

    fn empty(pinned_registry_key: [u8; 32]) -> Self {
        Self {
            pinned_registry_key,
            records_by_sequence: BTreeMap::new(),
            latest_sequence_by_account: BTreeMap::new(),
        }
    }

    fn restore(
        mut snapshot: RegistryCacheSnapshot,
        pinned_registry_key: [u8; 32],
    ) -> Result<Self, RegistryCacheError> {
        if snapshot.version != REGISTRY_CACHE_VERSION {
            return Err(RegistryCacheError::UnsupportedVersion(snapshot.version));
        }
        if snapshot.pinned_registry_key != pinned_registry_key {
            return Err(RegistryCacheError::PinnedRegistryKeyMismatch);
        }
        if snapshot.records.len() > MAX_REGISTRY_CACHE_ENTRIES {
            return Err(RegistryCacheError::CapacityExceeded);
        }
        snapshot
            .records
            .sort_by_key(|record| record.receipt.sequence);

        let mut cache = Self::empty(pinned_registry_key);
        for snapshot_record in snapshot.records {
            if cache
                .records_by_sequence
                .contains_key(&snapshot_record.receipt.sequence)
            {
                return Err(RegistryCacheError::InvalidCacheState);
            }
            let record = AcceptedRegistryRecord {
                claim: snapshot_record
                    .claim
                    .to_claim()
                    .map_err(RegistryCacheError::Registry)?,
                receipt: snapshot_record.receipt,
            };
            cache.apply_observation(record, snapshot_record.verified_at)?;
        }
        Ok(cache)
    }

    fn apply_observation(
        &mut self,
        record: AcceptedRegistryRecord,
        verified_at: u64,
    ) -> Result<(), RegistryCacheError> {
        if verified_at == 0 {
            return Err(RegistryCacheError::InvalidObservationTime);
        }
        record
            .verify(&self.pinned_registry_key)
            .map_err(RegistryCacheError::Registry)?;

        let account_id = record.receipt.account_id.clone();
        if let Some(previous) = self.latest_for_account(&account_id).cloned() {
            let cached_revision = previous.record.receipt.account_revision;
            let proposed_revision = record.receipt.account_revision;
            if proposed_revision < cached_revision {
                return Err(RegistryCacheError::AccountRollback {
                    cached: cached_revision,
                    proposed: proposed_revision,
                });
            }
            if proposed_revision == cached_revision {
                if record != previous.record {
                    return Err(RegistryCacheError::AccountEquivocation);
                }
                if verified_at < previous.verified_at {
                    return Err(RegistryCacheError::ObservationClockRollback {
                        cached: previous.verified_at,
                        proposed: verified_at,
                    });
                }
                let cached = self
                    .records_by_sequence
                    .get_mut(&record.receipt.sequence)
                    .ok_or(RegistryCacheError::InvalidCacheState)?;
                cached.verified_at = verified_at;
                return Ok(());
            }

            let expected_revision = cached_revision
                .checked_add(1)
                .ok_or(RegistryCacheError::InvalidCacheState)?;
            if proposed_revision != expected_revision {
                return Err(RegistryCacheError::AccountChainGap {
                    cached: cached_revision,
                    proposed: proposed_revision,
                });
            }
            if record.receipt.handle != previous.record.receipt.handle {
                return Err(RegistryCacheError::HandleEquivocation);
            }
            if record.receipt.accepted_at < previous.record.receipt.accepted_at {
                return Err(RegistryCacheError::RegistryTimeRollback);
            }
            if verified_at < previous.verified_at {
                return Err(RegistryCacheError::ObservationClockRollback {
                    cached: previous.verified_at,
                    proposed: verified_at,
                });
            }
            record
                .receipt
                .verify_account_after(&self.pinned_registry_key, Some(&previous.record.receipt))
                .map_err(RegistryCacheError::Registry)?;
        }

        if self.records_by_sequence.len() >= MAX_REGISTRY_CACHE_ENTRIES {
            return Err(RegistryCacheError::CapacityExceeded);
        }
        for cached in self.records_by_sequence.values() {
            if cached.record.receipt.account_id != account_id
                && cached.record.receipt.handle == record.receipt.handle
            {
                return Err(RegistryCacheError::HandleEquivocation);
            }
            if cached.record.receipt.account_id != account_id
                && cached.record.claim.binding().device_keys.nostr_public_key
                    == record.claim.binding().device_keys.nostr_public_key
            {
                return Err(RegistryCacheError::PrincipalEquivocation);
            }
        }

        let sequence = record.receipt.sequence;
        if self.records_by_sequence.contains_key(&sequence) {
            return Err(RegistryCacheError::SequenceEquivocation);
        }
        if sequence == 1 {
            record
                .receipt
                .verify_after(&self.pinned_registry_key, None)
                .map_err(RegistryCacheError::Registry)?;
        } else if let Some(previous) = self.records_by_sequence.get(&(sequence - 1)) {
            record
                .receipt
                .verify_after(&self.pinned_registry_key, Some(&previous.record.receipt))
                .map_err(RegistryCacheError::Registry)?;
        }
        if let Some(next_sequence) = sequence.checked_add(1)
            && let Some(next) = self.records_by_sequence.get(&next_sequence)
        {
            next.record
                .receipt
                .verify_after(&self.pinned_registry_key, Some(&record.receipt))
                .map_err(RegistryCacheError::Registry)?;
        }

        self.records_by_sequence.insert(
            sequence,
            CachedRegistryRecord {
                record,
                verified_at,
            },
        );
        self.latest_sequence_by_account.insert(account_id, sequence);
        Ok(())
    }

    fn latest_for_account(&self, account_id: &AccountId) -> Option<&CachedRegistryRecord> {
        self.latest_sequence_by_account
            .get(account_id)
            .and_then(|sequence| self.records_by_sequence.get(sequence))
    }

    fn latest_records(&self) -> impl Iterator<Item = &CachedRegistryRecord> {
        self.latest_sequence_by_account
            .values()
            .filter_map(|sequence| self.records_by_sequence.get(sequence))
    }

    fn persist(store: &SealedStore, cache: &Self) -> Result<(), RegistryCacheError> {
        let snapshot = RegistryCacheSnapshot {
            version: REGISTRY_CACHE_VERSION,
            pinned_registry_key: cache.pinned_registry_key,
            records: cache
                .records_by_sequence
                .values()
                .map(CachedRegistryRecordSnapshot::from_record)
                .collect(),
        };
        let mut encoded = Zeroizing::new(vec![0_u8; MAX_REGISTRY_CACHE_PLAINTEXT_BYTES]);
        let encoded_bytes = {
            let mut writer = Cursor::new(&mut encoded[..]);
            serde_json::to_writer(&mut writer, &snapshot)
                .map_err(|_| RegistryCacheError::Encoding)?;
            usize::try_from(writer.position()).map_err(|_| RegistryCacheError::Encoding)?
        };
        store
            .write(REGISTRY_CACHE_RECORD, &encoded[..encoded_bytes])
            .map_err(RegistryCacheError::Store)
    }
}

fn classify(record: &CachedRegistryRecord, now: u64, max_age_seconds: u64) -> RegistryCacheLookup {
    let record = record.clone();
    match now.checked_sub(record.verified_at) {
        None => RegistryCacheLookup::UnusableClockRollback(record),
        Some(age) if age <= max_age_seconds => RegistryCacheLookup::Fresh(record),
        Some(_) => RegistryCacheLookup::OfflineStale(record),
    }
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct RegistryCacheSnapshot {
    version: u16,
    pinned_registry_key: [u8; 32],
    records: Vec<CachedRegistryRecordSnapshot>,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct CachedRegistryRecordSnapshot {
    claim: HandleClaimSnapshot,
    receipt: RegistryReceipt,
    verified_at: u64,
}

impl CachedRegistryRecordSnapshot {
    fn from_record(record: &CachedRegistryRecord) -> Self {
        Self {
            claim: HandleClaimSnapshot::from_claim(&record.record.claim),
            receipt: record.record.receipt.clone(),
            verified_at: record.verified_at,
        }
    }
}

#[derive(Debug)]
pub enum RegistryCacheError {
    Store(StoreError),
    Registry(RegistryError),
    Encoding,
    UnsupportedVersion(u16),
    PinnedRegistryKeyMismatch,
    InvalidCacheState,
    InvalidObservationTime,
    CapacityExceeded,
    ObservationClockRollback { cached: u64, proposed: u64 },
    RegistryTimeRollback,
    AccountRollback { cached: u64, proposed: u64 },
    AccountChainGap { cached: u64, proposed: u64 },
    AccountEquivocation,
    HandleEquivocation,
    PrincipalEquivocation,
    SequenceEquivocation,
}

impl fmt::Display for RegistryCacheError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Store(error) => write!(formatter, "registry cache storage failed: {error}"),
            Self::Registry(error) => write!(formatter, "registry evidence is invalid: {error}"),
            Self::Encoding => formatter.write_str("registry cache encoding is invalid"),
            Self::UnsupportedVersion(version) => {
                write!(formatter, "unsupported registry cache version {version}")
            }
            Self::PinnedRegistryKeyMismatch => {
                formatter.write_str("registry cache was sealed for a different pinned key")
            }
            Self::InvalidCacheState => formatter.write_str("registry cache state is inconsistent"),
            Self::InvalidObservationTime => {
                formatter.write_str("registry evidence observation time must be non-zero")
            }
            Self::CapacityExceeded => formatter.write_str("registry cache capacity is exhausted"),
            Self::ObservationClockRollback { cached, proposed } => write!(
                formatter,
                "registry observation clock rolled back from {cached} to {proposed}"
            ),
            Self::RegistryTimeRollback => {
                formatter.write_str("registry acceptance time moved backwards")
            }
            Self::AccountRollback { cached, proposed } => write!(
                formatter,
                "registry account revision rolled back from {cached} to {proposed}"
            ),
            Self::AccountChainGap { cached, proposed } => write!(
                formatter,
                "registry account chain jumps from revision {cached} to {proposed}"
            ),
            Self::AccountEquivocation => formatter
                .write_str("registry returned conflicting evidence for one account revision"),
            Self::HandleEquivocation => {
                formatter.write_str("registry returned conflicting ownership for one handle")
            }
            Self::PrincipalEquivocation => formatter
                .write_str("registry returned conflicting account ownership for one Nostr key"),
            Self::SequenceEquivocation => formatter
                .write_str("registry returned conflicting evidence for one global sequence"),
        }
    }
}

impl Error for RegistryCacheError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Store(error) => Some(error),
            Self::Registry(error) => Some(error),
            _ => None,
        }
    }
}
