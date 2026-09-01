use crate::{SealedStore, StoreError};
use omachat_crypto::{AccountId, GlobalHandle};
use omachat_registry::{
    HandleClaimSnapshot, RegistryError, RegistryReceipt,
    principal_proof::NostrPrincipalControlProof, principal_receipt::PrincipalProofReceipt,
    principal_registry::PrincipalRegistryRecord,
    proof_bearing_claim::ProofBearingDeviceHandleClaim,
};
use serde::{Deserialize, Serialize};
use std::{collections::BTreeMap, error::Error, fmt, io::Cursor};
use zeroize::Zeroizing;

const PRINCIPAL_REGISTRY_CACHE_RECORD: &str = "principal-registry-cache-v1";
const PRINCIPAL_REGISTRY_CACHE_VERSION: u16 = 1;
const MAX_PRINCIPAL_REGISTRY_CACHE_ENTRIES: usize = 512;
const MAX_PRINCIPAL_REGISTRY_CACHE_PLAINTEXT_BYTES: usize = 4 * 1024 * 1024;

/// Exact independently verified root claim, principal proof, and both receipts.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PrincipalRegistryEvidence {
    pub claim: ProofBearingDeviceHandleClaim,
    pub claim_receipt: RegistryReceipt,
    pub principal_receipt: PrincipalProofReceipt,
}

impl PrincipalRegistryEvidence {
    #[must_use]
    pub fn from_record(record: &PrincipalRegistryRecord) -> Self {
        Self {
            claim: ProofBearingDeviceHandleClaim::new(
                record.claim().clone(),
                record.principal_proof().clone(),
            )
            .expect("authoritative principal record must retain its validated claim"),
            claim_receipt: record.claim_receipt().clone(),
            principal_receipt: record.principal_receipt().clone(),
        }
    }

    fn verify(&self, pinned_registry_key: &[u8; 32]) -> Result<(), PrincipalRegistryCacheError> {
        self.claim_receipt
            .verify_for_claim(pinned_registry_key, self.claim.claim())
            .map_err(PrincipalRegistryCacheError::Registry)?;
        self.principal_receipt
            .verify_for(pinned_registry_key, &self.claim, &self.claim_receipt)
            .map_err(|_| PrincipalRegistryCacheError::InvalidPrincipalReceipt)
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CachedPrincipalRegistryRecord {
    pub evidence: PrincipalRegistryEvidence,
    pub verified_at: u64,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum PrincipalRegistryCacheLookup {
    Missing,
    Fresh(CachedPrincipalRegistryRecord),
    OfflineStale(CachedPrincipalRegistryRecord),
    UnusableClockRollback(CachedPrincipalRegistryRecord),
}

impl PrincipalRegistryCacheLookup {
    #[must_use]
    pub const fn record(&self) -> Option<&CachedPrincipalRegistryRecord> {
        match self {
            Self::Missing => None,
            Self::Fresh(record)
            | Self::OfflineStale(record)
            | Self::UnusableClockRollback(record) => Some(record),
        }
    }
}

/// Bounded sealed cache for independently proven Nostr principal bindings.
#[derive(Clone, Debug)]
pub struct VerifiedPrincipalRegistryCache {
    pinned_registry_key: [u8; 32],
    records_by_sequence: BTreeMap<u64, CachedPrincipalRegistryRecord>,
    latest_sequence_by_account: BTreeMap<AccountId, u64>,
    latest_sequence_by_public_key: BTreeMap<[u8; 32], u64>,
}

impl VerifiedPrincipalRegistryCache {
    pub fn load_or_create(
        store: &SealedStore,
        pinned_registry_key: [u8; 32],
    ) -> Result<Self, PrincipalRegistryCacheError> {
        match store.read(PRINCIPAL_REGISTRY_CACHE_RECORD) {
            Ok(bytes) => {
                let bytes = Zeroizing::new(bytes);
                let snapshot: PrincipalRegistryCacheSnapshot = serde_json::from_slice(&bytes)
                    .map_err(|_| PrincipalRegistryCacheError::Encoding)?;
                Self::restore(snapshot, pinned_registry_key)
            }
            Err(StoreError::RecordNotFound) => {
                let cache = Self::empty(pinned_registry_key);
                Self::persist(store, &cache)?;
                Ok(cache)
            }
            Err(error) => Err(PrincipalRegistryCacheError::Store(error)),
        }
    }

    /// Reverify and seal evidence before advancing the in-memory cache.
    pub fn observe(
        &mut self,
        store: &SealedStore,
        evidence: PrincipalRegistryEvidence,
        verified_at: u64,
    ) -> Result<(), PrincipalRegistryCacheError> {
        let mut candidate = self.clone();
        candidate.apply_observation(evidence, verified_at)?;
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
    ) -> PrincipalRegistryCacheLookup {
        self.latest_for_account(account_id)
            .map_or(PrincipalRegistryCacheLookup::Missing, |record| {
                classify(record, now, max_age_seconds)
            })
    }

    #[must_use]
    pub fn lookup_handle(
        &self,
        handle: &GlobalHandle,
        now: u64,
        max_age_seconds: u64,
    ) -> PrincipalRegistryCacheLookup {
        self.latest_records()
            .find(|record| record.evidence.claim_receipt.handle.as_global_handle() == handle)
            .map_or(PrincipalRegistryCacheLookup::Missing, |record| {
                classify(record, now, max_age_seconds)
            })
    }

    #[must_use]
    pub fn lookup_public_key(
        &self,
        public_key: &[u8; 32],
        now: u64,
        max_age_seconds: u64,
    ) -> PrincipalRegistryCacheLookup {
        self.latest_sequence_by_public_key
            .get(public_key)
            .and_then(|sequence| self.records_by_sequence.get(sequence))
            .map_or(PrincipalRegistryCacheLookup::Missing, |record| {
                classify(record, now, max_age_seconds)
            })
    }

    fn empty(pinned_registry_key: [u8; 32]) -> Self {
        Self {
            pinned_registry_key,
            records_by_sequence: BTreeMap::new(),
            latest_sequence_by_account: BTreeMap::new(),
            latest_sequence_by_public_key: BTreeMap::new(),
        }
    }

    fn restore(
        mut snapshot: PrincipalRegistryCacheSnapshot,
        pinned_registry_key: [u8; 32],
    ) -> Result<Self, PrincipalRegistryCacheError> {
        if snapshot.version != PRINCIPAL_REGISTRY_CACHE_VERSION {
            return Err(PrincipalRegistryCacheError::UnsupportedVersion(
                snapshot.version,
            ));
        }
        if snapshot.pinned_registry_key != pinned_registry_key {
            return Err(PrincipalRegistryCacheError::PinnedRegistryKeyMismatch);
        }
        if snapshot.records.len() > MAX_PRINCIPAL_REGISTRY_CACHE_ENTRIES {
            return Err(PrincipalRegistryCacheError::CapacityExceeded);
        }
        snapshot
            .records
            .sort_by_key(|record| record.claim_receipt.sequence);
        let mut cache = Self::empty(pinned_registry_key);
        for record in snapshot.records {
            if cache
                .records_by_sequence
                .contains_key(&record.claim_receipt.sequence)
            {
                return Err(PrincipalRegistryCacheError::InvalidCacheState);
            }
            let root_claim = record
                .claim
                .to_claim()
                .map_err(PrincipalRegistryCacheError::Registry)?;
            let proof = NostrPrincipalControlProof::from_bytes(
                &hex::decode(record.principal_proof_hex)
                    .map_err(|_| PrincipalRegistryCacheError::Encoding)?,
            )
            .map_err(|_| PrincipalRegistryCacheError::InvalidPrincipalClaim)?;
            let claim = ProofBearingDeviceHandleClaim::new(root_claim, proof)
                .map_err(|_| PrincipalRegistryCacheError::InvalidPrincipalClaim)?;
            let principal_receipt = PrincipalProofReceipt::from_bytes_for_claim_receipt(
                &hex::decode(record.principal_receipt_hex)
                    .map_err(|_| PrincipalRegistryCacheError::Encoding)?,
                &record.claim_receipt,
                &pinned_registry_key,
            )
            .map_err(|_| PrincipalRegistryCacheError::InvalidPrincipalReceipt)?;
            cache.apply_observation(
                PrincipalRegistryEvidence {
                    claim,
                    claim_receipt: record.claim_receipt,
                    principal_receipt,
                },
                record.verified_at,
            )?;
        }
        Ok(cache)
    }

    fn apply_observation(
        &mut self,
        evidence: PrincipalRegistryEvidence,
        verified_at: u64,
    ) -> Result<(), PrincipalRegistryCacheError> {
        if verified_at == 0 {
            return Err(PrincipalRegistryCacheError::InvalidObservationTime);
        }
        evidence.verify(&self.pinned_registry_key)?;
        let account_id = evidence.claim_receipt.account_id.clone();
        let public_key = evidence
            .claim
            .principal_proof()
            .payload()
            .nostr_public_key();

        if let Some(previous) = self.latest_for_account(&account_id).cloned() {
            let cached_revision = previous.evidence.claim_receipt.account_revision;
            let proposed_revision = evidence.claim_receipt.account_revision;
            if proposed_revision < cached_revision {
                return Err(PrincipalRegistryCacheError::AccountRollback {
                    cached: cached_revision,
                    proposed: proposed_revision,
                });
            }
            if proposed_revision == cached_revision {
                if evidence != previous.evidence {
                    return Err(PrincipalRegistryCacheError::AccountEquivocation);
                }
                if verified_at < previous.verified_at {
                    return Err(PrincipalRegistryCacheError::ObservationClockRollback {
                        cached: previous.verified_at,
                        proposed: verified_at,
                    });
                }
                let cached = self
                    .records_by_sequence
                    .get_mut(&evidence.claim_receipt.sequence)
                    .ok_or(PrincipalRegistryCacheError::InvalidCacheState)?;
                cached.verified_at = verified_at;
                return Ok(());
            }

            let expected_revision = cached_revision
                .checked_add(1)
                .ok_or(PrincipalRegistryCacheError::InvalidCacheState)?;
            if proposed_revision != expected_revision {
                return Err(PrincipalRegistryCacheError::AccountChainGap {
                    cached: cached_revision,
                    proposed: proposed_revision,
                });
            }
            if evidence.claim_receipt.handle != previous.evidence.claim_receipt.handle {
                return Err(PrincipalRegistryCacheError::HandleEquivocation);
            }
            if evidence.claim_receipt.accepted_at < previous.evidence.claim_receipt.accepted_at {
                return Err(PrincipalRegistryCacheError::RegistryTimeRollback);
            }
            if verified_at < previous.verified_at {
                return Err(PrincipalRegistryCacheError::ObservationClockRollback {
                    cached: previous.verified_at,
                    proposed: verified_at,
                });
            }
            evidence
                .claim_receipt
                .verify_account_after(
                    &self.pinned_registry_key,
                    Some(&previous.evidence.claim_receipt),
                )
                .map_err(PrincipalRegistryCacheError::Registry)?;
            evidence
                .principal_receipt
                .verify_account_after(
                    &self.pinned_registry_key,
                    Some(&previous.evidence.principal_receipt),
                )
                .map_err(|_| PrincipalRegistryCacheError::InvalidPrincipalReceipt)?;
        }

        if self.records_by_sequence.len() >= MAX_PRINCIPAL_REGISTRY_CACHE_ENTRIES {
            return Err(PrincipalRegistryCacheError::CapacityExceeded);
        }
        for cached in self.latest_records() {
            if cached.evidence.claim_receipt.account_id != account_id
                && cached.evidence.claim_receipt.handle == evidence.claim_receipt.handle
            {
                return Err(PrincipalRegistryCacheError::HandleEquivocation);
            }
        }
        if let Some(existing_sequence) = self.latest_sequence_by_public_key.get(&public_key) {
            let existing = self
                .records_by_sequence
                .get(existing_sequence)
                .ok_or(PrincipalRegistryCacheError::InvalidCacheState)?;
            if existing.evidence.claim_receipt.account_id != account_id {
                return Err(PrincipalRegistryCacheError::PrincipalEquivocation);
            }
        }

        let sequence = evidence.claim_receipt.sequence;
        if self.records_by_sequence.contains_key(&sequence) {
            return Err(PrincipalRegistryCacheError::SequenceEquivocation);
        }
        if sequence == 1 {
            evidence
                .claim_receipt
                .verify_after(&self.pinned_registry_key, None)
                .map_err(PrincipalRegistryCacheError::Registry)?;
            evidence
                .principal_receipt
                .verify_after(&self.pinned_registry_key, None)
                .map_err(|_| PrincipalRegistryCacheError::InvalidPrincipalReceipt)?;
        } else if let Some(previous) = self.records_by_sequence.get(&(sequence - 1)) {
            evidence
                .claim_receipt
                .verify_after(
                    &self.pinned_registry_key,
                    Some(&previous.evidence.claim_receipt),
                )
                .map_err(PrincipalRegistryCacheError::Registry)?;
            evidence
                .principal_receipt
                .verify_after(
                    &self.pinned_registry_key,
                    Some(&previous.evidence.principal_receipt),
                )
                .map_err(|_| PrincipalRegistryCacheError::InvalidPrincipalReceipt)?;
        }
        if let Some(next_sequence) = sequence.checked_add(1)
            && let Some(next) = self.records_by_sequence.get(&next_sequence)
        {
            next.evidence
                .claim_receipt
                .verify_after(&self.pinned_registry_key, Some(&evidence.claim_receipt))
                .map_err(PrincipalRegistryCacheError::Registry)?;
            next.evidence
                .principal_receipt
                .verify_after(&self.pinned_registry_key, Some(&evidence.principal_receipt))
                .map_err(|_| PrincipalRegistryCacheError::InvalidPrincipalReceipt)?;
        }

        if let Some(previous_sequence) = self.latest_sequence_by_account.get(&account_id)
            && let Some(previous) = self.records_by_sequence.get(previous_sequence)
        {
            let previous_key = previous
                .evidence
                .claim
                .principal_proof()
                .payload()
                .nostr_public_key();
            if previous_key != public_key {
                self.latest_sequence_by_public_key.remove(&previous_key);
            }
        }
        self.records_by_sequence.insert(
            sequence,
            CachedPrincipalRegistryRecord {
                evidence,
                verified_at,
            },
        );
        self.latest_sequence_by_account.insert(account_id, sequence);
        self.latest_sequence_by_public_key
            .insert(public_key, sequence);
        Ok(())
    }

    fn latest_for_account(&self, account_id: &AccountId) -> Option<&CachedPrincipalRegistryRecord> {
        self.latest_sequence_by_account
            .get(account_id)
            .and_then(|sequence| self.records_by_sequence.get(sequence))
    }

    fn latest_records(&self) -> impl Iterator<Item = &CachedPrincipalRegistryRecord> {
        self.latest_sequence_by_account
            .values()
            .filter_map(|sequence| self.records_by_sequence.get(sequence))
    }

    fn persist(store: &SealedStore, cache: &Self) -> Result<(), PrincipalRegistryCacheError> {
        let snapshot = PrincipalRegistryCacheSnapshot {
            version: PRINCIPAL_REGISTRY_CACHE_VERSION,
            pinned_registry_key: cache.pinned_registry_key,
            records: cache
                .records_by_sequence
                .values()
                .map(CachedPrincipalRegistryRecordSnapshot::from_record)
                .collect(),
        };
        let mut encoded = Zeroizing::new(vec![0_u8; MAX_PRINCIPAL_REGISTRY_CACHE_PLAINTEXT_BYTES]);
        let encoded_bytes = {
            let mut writer = Cursor::new(&mut encoded[..]);
            serde_json::to_writer(&mut writer, &snapshot)
                .map_err(|_| PrincipalRegistryCacheError::Encoding)?;
            usize::try_from(writer.position()).map_err(|_| PrincipalRegistryCacheError::Encoding)?
        };
        store
            .write(PRINCIPAL_REGISTRY_CACHE_RECORD, &encoded[..encoded_bytes])
            .map_err(PrincipalRegistryCacheError::Store)
    }
}

fn classify(
    record: &CachedPrincipalRegistryRecord,
    now: u64,
    max_age_seconds: u64,
) -> PrincipalRegistryCacheLookup {
    let record = record.clone();
    match now.checked_sub(record.verified_at) {
        None => PrincipalRegistryCacheLookup::UnusableClockRollback(record),
        Some(age) if age <= max_age_seconds => PrincipalRegistryCacheLookup::Fresh(record),
        Some(_) => PrincipalRegistryCacheLookup::OfflineStale(record),
    }
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct PrincipalRegistryCacheSnapshot {
    version: u16,
    pinned_registry_key: [u8; 32],
    records: Vec<CachedPrincipalRegistryRecordSnapshot>,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct CachedPrincipalRegistryRecordSnapshot {
    claim: HandleClaimSnapshot,
    principal_proof_hex: String,
    claim_receipt: RegistryReceipt,
    principal_receipt_hex: String,
    verified_at: u64,
}

impl CachedPrincipalRegistryRecordSnapshot {
    fn from_record(record: &CachedPrincipalRegistryRecord) -> Self {
        Self {
            claim: HandleClaimSnapshot::from_claim(record.evidence.claim.claim()),
            principal_proof_hex: hex::encode(record.evidence.claim.principal_proof().to_bytes()),
            claim_receipt: record.evidence.claim_receipt.clone(),
            principal_receipt_hex: hex::encode(record.evidence.principal_receipt.to_bytes()),
            verified_at: record.verified_at,
        }
    }
}

#[derive(Debug)]
pub enum PrincipalRegistryCacheError {
    Store(StoreError),
    Registry(RegistryError),
    Encoding,
    UnsupportedVersion(u16),
    PinnedRegistryKeyMismatch,
    InvalidCacheState,
    InvalidPrincipalClaim,
    InvalidPrincipalReceipt,
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

impl fmt::Display for PrincipalRegistryCacheError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Store(error) => write!(formatter, "principal registry cache failed: {error}"),
            Self::Registry(error) => {
                write!(formatter, "root registry evidence is invalid: {error}")
            }
            Self::Encoding => formatter.write_str("principal registry cache encoding is invalid"),
            Self::UnsupportedVersion(version) => {
                write!(
                    formatter,
                    "unsupported principal registry cache version {version}"
                )
            }
            Self::PinnedRegistryKeyMismatch => formatter
                .write_str("principal registry cache was sealed for a different pinned key"),
            Self::InvalidCacheState => {
                formatter.write_str("principal registry cache state is inconsistent")
            }
            Self::InvalidPrincipalClaim => formatter.write_str("cached principal claim is invalid"),
            Self::InvalidPrincipalReceipt => {
                formatter.write_str("cached principal receipt is invalid")
            }
            Self::InvalidObservationTime => {
                formatter.write_str("principal evidence observation time must be non-zero")
            }
            Self::CapacityExceeded => {
                formatter.write_str("principal registry cache capacity is exhausted")
            }
            Self::ObservationClockRollback { cached, proposed } => write!(
                formatter,
                "principal observation clock rolled back from {cached} to {proposed}"
            ),
            Self::RegistryTimeRollback => {
                formatter.write_str("principal registry acceptance time moved backwards")
            }
            Self::AccountRollback { cached, proposed } => write!(
                formatter,
                "principal account revision rolled back from {cached} to {proposed}"
            ),
            Self::AccountChainGap { cached, proposed } => write!(
                formatter,
                "principal account chain jumps from revision {cached} to {proposed}"
            ),
            Self::AccountEquivocation => formatter
                .write_str("registry returned conflicting principal evidence for one revision"),
            Self::HandleEquivocation => formatter
                .write_str("registry returned conflicting principal ownership for one handle"),
            Self::PrincipalEquivocation => formatter
                .write_str("registry returned conflicting ownership for one live Nostr key"),
            Self::SequenceEquivocation => formatter
                .write_str("registry returned conflicting principal evidence for one sequence"),
        }
    }
}

impl Error for PrincipalRegistryCacheError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Store(error) => Some(error),
            Self::Registry(error) => Some(error),
            _ => None,
        }
    }
}
