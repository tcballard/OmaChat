use std::collections::{BTreeMap, BTreeSet};
use std::error::Error;
use std::fmt;
use std::net::IpAddr;

use serde::{Deserialize, Serialize};
use url::Url;

use crate::event::{EventLimits, SignedEvent};
use crate::inbox::{DmInboxPolicy, verify_dm_inbox};

pub const MAX_CACHED_DM_RECIPIENTS: usize = 4_096;
pub const MAX_DM_RELAYS_PER_RECIPIENT: usize = 3;
pub const MAX_DM_RELAY_ENDPOINT_BYTES: usize = 2_048;
const MAX_SERIALIZED_CACHE_BYTES: usize = 1_048_576;
const CACHE_FORMAT_VERSION: u8 = 1;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VerifiedDmRelayRecord {
    recipient_pubkey: [u8; 32],
    source_event_id: [u8; 32],
    source_created_at: u64,
    verified_at: u64,
    relays: Vec<String>,
    source_event: SignedEvent,
}

impl VerifiedDmRelayRecord {
    pub fn recipient_pubkey(&self) -> &[u8; 32] {
        &self.recipient_pubkey
    }

    pub fn source_event_id(&self) -> &[u8; 32] {
        &self.source_event_id
    }

    pub fn source_created_at(&self) -> u64 {
        self.source_created_at
    }

    pub fn verified_at(&self) -> u64 {
        self.verified_at
    }

    pub fn relays(&self) -> &[String] {
        &self.relays
    }

    pub fn source_event(&self) -> &SignedEvent {
        &self.source_event
    }

    pub(crate) fn from_authenticated_event(
        recipient_pubkey: [u8; 32],
        source_event_id: [u8; 32],
        source_created_at: u64,
        verified_at: u64,
        relays: Vec<String>,
        source_event: SignedEvent,
    ) -> Result<Self, DmRelayCacheError> {
        let mut record = Self {
            recipient_pubkey,
            source_event_id,
            source_created_at,
            verified_at,
            relays,
            source_event,
        };
        record.canonicalize_and_validate()?;
        Ok(record)
    }

    fn canonicalize_and_validate(&mut self) -> Result<(), DmRelayCacheError> {
        if self.recipient_pubkey == [0; 32] {
            return Err(DmRelayCacheError::InvalidRecipient);
        }
        if self.source_event_id == [0; 32] {
            return Err(DmRelayCacheError::InvalidSourceEvent);
        }
        if self.verified_at < self.source_created_at {
            return Err(DmRelayCacheError::InvalidVerificationTime);
        }
        if self.source_event.pubkey != hex::encode(self.recipient_pubkey)
            || self.source_event.id != hex::encode(self.source_event_id)
            || self.source_event.created_at != self.source_created_at
        {
            return Err(DmRelayCacheError::SourceBindingMismatch);
        }
        if self.relays.len() > MAX_DM_RELAYS_PER_RECIPIENT {
            return Err(DmRelayCacheError::TooManyRelays);
        }

        let mut canonical = Vec::with_capacity(self.relays.len());
        let mut seen = BTreeSet::new();
        for endpoint in &self.relays {
            if endpoint.len() > MAX_DM_RELAY_ENDPOINT_BYTES {
                return Err(DmRelayCacheError::EndpointTooLong);
            }
            let parsed = Url::parse(endpoint).map_err(|_| DmRelayCacheError::InvalidEndpoint)?;
            let secure_or_loopback = parsed.scheme() == "wss"
                || (parsed.scheme() == "ws"
                    && parsed
                        .host_str()
                        .and_then(|host| host.parse::<IpAddr>().ok())
                        .is_some_and(|address| address.is_loopback()));
            if !secure_or_loopback
                || parsed.host_str().is_none()
                || !parsed.username().is_empty()
                || parsed.password().is_some()
                || parsed.fragment().is_some()
            {
                return Err(DmRelayCacheError::InvalidEndpoint);
            }
            let endpoint = parsed.to_string();
            if !seen.insert(endpoint.clone()) {
                return Err(DmRelayCacheError::DuplicateEndpoint);
            }
            canonical.push(endpoint);
        }
        canonical.sort();
        self.relays = canonical;
        Ok(())
    }
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct VerifiedDmRelayCache {
    records: BTreeMap<String, VerifiedDmRelayRecord>,
}

impl VerifiedDmRelayCache {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn len(&self) -> usize {
        self.records.len()
    }

    pub fn is_empty(&self) -> bool {
        self.records.is_empty()
    }

    pub fn insert(
        &mut self,
        mut record: VerifiedDmRelayRecord,
    ) -> Result<CacheMutation, DmRelayCacheError> {
        record.canonicalize_and_validate()?;
        let recipient_key = hex::encode(record.recipient_pubkey);

        if let Some(current) = self.records.get(&recipient_key) {
            if record.source_created_at < current.source_created_at {
                return Err(DmRelayCacheError::Rollback);
            }
            if record.source_created_at == current.source_created_at {
                if record.source_event_id != current.source_event_id {
                    return Err(DmRelayCacheError::Equivocation);
                }
                if record.relays != current.relays || record.source_event != current.source_event {
                    return Err(DmRelayCacheError::SourceBindingMismatch);
                }
                return Ok(CacheMutation::Unchanged);
            }
        } else if self.records.len() >= MAX_CACHED_DM_RECIPIENTS {
            return Err(DmRelayCacheError::CacheFull);
        }

        let previous = self.records.insert(recipient_key.clone(), record);
        if let Err(error) = self.to_json() {
            if let Some(previous) = previous {
                self.records.insert(recipient_key, previous);
            } else {
                self.records.remove(&recipient_key);
            }
            return Err(error);
        }
        Ok(CacheMutation::Stored)
    }

    pub fn lookup(
        &self,
        recipient_pubkey: &[u8; 32],
        now: u64,
        freshness_window_secs: u64,
    ) -> DmRelayCacheLookup<'_> {
        let recipient_key = hex::encode(recipient_pubkey);
        let Some(record) = self.records.get(&recipient_key) else {
            return DmRelayCacheLookup::Missing;
        };
        let Some(age) = now.checked_sub(record.source_created_at) else {
            return DmRelayCacheLookup::UnusableClockRollback(record);
        };
        if age <= freshness_window_secs {
            DmRelayCacheLookup::Fresh(record)
        } else {
            DmRelayCacheLookup::OfflineStale(record)
        }
    }

    pub fn to_json(&self) -> Result<Vec<u8>, DmRelayCacheError> {
        let persisted = PersistedDmRelayCache {
            version: CACHE_FORMAT_VERSION,
            records: self
                .records
                .values()
                .map(|record| PersistedDmRelayRecord {
                    verified_at: record.verified_at,
                    source_event: record.source_event.clone(),
                })
                .collect(),
        };
        let encoded =
            serde_json::to_vec(&persisted).map_err(|_| DmRelayCacheError::InvalidEncoding)?;
        if encoded.len() > MAX_SERIALIZED_CACHE_BYTES {
            return Err(DmRelayCacheError::CacheTooLarge);
        }
        Ok(encoded)
    }

    pub fn from_json(
        encoded: &[u8],
        now: u64,
        event_limits: &EventLimits,
        policy: &DmInboxPolicy,
    ) -> Result<Self, DmRelayCacheError> {
        if encoded.len() > MAX_SERIALIZED_CACHE_BYTES {
            return Err(DmRelayCacheError::CacheTooLarge);
        }
        let persisted: PersistedDmRelayCache =
            serde_json::from_slice(encoded).map_err(|_| DmRelayCacheError::InvalidEncoding)?;
        if persisted.version != CACHE_FORMAT_VERSION {
            return Err(DmRelayCacheError::UnsupportedVersion);
        }
        if persisted.records.len() > MAX_CACHED_DM_RECIPIENTS {
            return Err(DmRelayCacheError::CacheFull);
        }

        let stale_tolerant_policy = DmInboxPolicy {
            maximum_age_seconds: u64::MAX,
            ..*policy
        };
        let mut seen = BTreeSet::new();
        let mut cache = Self::new();
        for persisted_record in persisted.records {
            if persisted_record.verified_at > now {
                return Err(DmRelayCacheError::InvalidVerificationTime);
            }
            let mut recipient = [0; 32];
            hex::decode_to_slice(&persisted_record.source_event.pubkey, &mut recipient)
                .map_err(|_| DmRelayCacheError::InvalidRecipient)?;
            if !seen.insert(recipient) {
                return Err(DmRelayCacheError::InvalidEncoding);
            }
            let verified = verify_dm_inbox(
                &persisted_record.source_event,
                &recipient,
                now,
                event_limits,
                &stale_tolerant_policy,
            )
            .map_err(|_| DmRelayCacheError::InvalidSourceEvent)?;
            let record = verified.to_cache_record(persisted_record.verified_at)?;
            cache.insert(record)?;
        }
        Ok(cache)
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct PersistedDmRelayCache {
    version: u8,
    records: Vec<PersistedDmRelayRecord>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct PersistedDmRelayRecord {
    verified_at: u64,
    source_event: SignedEvent,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CacheMutation {
    Stored,
    Unchanged,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DmRelayCacheLookup<'a> {
    Missing,
    Fresh(&'a VerifiedDmRelayRecord),
    OfflineStale(&'a VerifiedDmRelayRecord),
    UnusableClockRollback(&'a VerifiedDmRelayRecord),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DmRelayCacheError {
    InvalidRecipient,
    InvalidSourceEvent,
    InvalidVerificationTime,
    InvalidEndpoint,
    EndpointTooLong,
    DuplicateEndpoint,
    TooManyRelays,
    CacheFull,
    CacheTooLarge,
    InvalidEncoding,
    UnsupportedVersion,
    Rollback,
    Equivocation,
    SourceBindingMismatch,
}

impl fmt::Display for DmRelayCacheError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::InvalidRecipient => "invalid DM relay recipient",
            Self::InvalidSourceEvent => "invalid signed DM relay source event",
            Self::InvalidVerificationTime => "invalid DM relay verification time",
            Self::InvalidEndpoint => "invalid DM relay endpoint",
            Self::EndpointTooLong => "DM relay endpoint exceeds the configured bound",
            Self::DuplicateEndpoint => "duplicate DM relay endpoint",
            Self::TooManyRelays => "too many DM relay endpoints",
            Self::CacheFull => "DM relay cache is full",
            Self::CacheTooLarge => "serialized DM relay cache exceeds the configured bound",
            Self::InvalidEncoding => "invalid DM relay cache encoding",
            Self::UnsupportedVersion => "unsupported DM relay cache version",
            Self::Rollback => "older DM relay metadata cannot replace newer state",
            Self::Equivocation => "conflicting DM relay events share a timestamp",
            Self::SourceBindingMismatch => "DM relay data does not match its signed source event",
        })
    }
}

impl Error for DmRelayCacheError {}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::discovery::NIP17_DM_RELAY_LIST_KIND;
    use crate::event::{UnsignedEvent, xonly_public_key};

    const NOW: u64 = 1_800_000_000;

    fn record(
        secret_byte: u8,
        created_at: u64,
        relays: &[&str],
    ) -> ([u8; 32], VerifiedDmRelayRecord) {
        let secret = [secret_byte; 32];
        let recipient = xonly_public_key(&secret).expect("valid recipient public key");
        let event = UnsignedEvent::new(
            hex::encode(recipient),
            created_at,
            NIP17_DM_RELAY_LIST_KIND,
            relays
                .iter()
                .map(|relay| vec!["relay".to_owned(), (*relay).to_owned()])
                .collect(),
            String::new(),
            &EventLimits::default(),
        )
        .expect("valid relay list")
        .sign_with_aux(&secret, &[7; 32], &EventLimits::default())
        .expect("signed relay list");
        let verified = verify_dm_inbox(
            &event,
            &recipient,
            NOW,
            &EventLimits::default(),
            &DmInboxPolicy::default(),
        )
        .expect("verified relay list");
        let record = verified.to_cache_record(NOW).expect("cache record");
        (recipient, record)
    }

    #[test]
    fn freshness_and_offline_use_are_explicit() {
        let (recipient, record) = record(1, NOW - 10, &["wss://relay.example"]);
        let mut cache = VerifiedDmRelayCache::new();
        cache.insert(record).expect("store record");

        assert!(matches!(
            cache.lookup(&recipient, NOW, 10),
            DmRelayCacheLookup::Fresh(_)
        ));
        assert!(matches!(
            cache.lookup(&recipient, NOW + 1, 10),
            DmRelayCacheLookup::OfflineStale(_)
        ));
        assert!(matches!(
            cache.lookup(&recipient, NOW - 11, 10),
            DmRelayCacheLookup::UnusableClockRollback(_)
        ));
    }

    #[test]
    fn rollback_equivocation_and_rebound_payloads_fail_closed() {
        let (_, original) = record(3, NOW - 100, &["wss://one.example"]);
        let mut cache = VerifiedDmRelayCache::new();
        assert_eq!(cache.insert(original.clone()), Ok(CacheMutation::Stored));
        assert_eq!(cache.insert(original.clone()), Ok(CacheMutation::Unchanged));
        assert_eq!(
            cache.insert(record(3, NOW - 101, &["wss://two.example"]).1),
            Err(DmRelayCacheError::Rollback)
        );
        assert_eq!(
            cache.insert(record(3, NOW - 100, &["wss://two.example"]).1),
            Err(DmRelayCacheError::Equivocation)
        );

        let mut rebound = original;
        rebound.relays = vec!["wss://two.example/".into()];
        assert_eq!(
            cache.insert(rebound),
            Err(DmRelayCacheError::SourceBindingMismatch)
        );
    }

    #[test]
    fn canonical_endpoints_are_deterministic_and_duplicates_are_rejected() {
        let (_, record) = record(6, NOW - 20, &["wss://z.example", "wss://a.example/path"]);
        assert_eq!(
            record.relays(),
            &["wss://a.example/path", "wss://z.example/"]
        );
        assert_eq!(
            VerifiedDmRelayRecord::from_authenticated_event(
                record.recipient_pubkey,
                record.source_event_id,
                record.source_created_at,
                record.verified_at,
                vec!["wss://same.example".into(), "wss://same.example/".into()],
                record.source_event.clone(),
            ),
            Err(DmRelayCacheError::DuplicateEndpoint)
        );
    }

    #[test]
    fn persisted_records_are_cryptographically_reverified_before_use() {
        let (_, record) = record(9, NOW - 30, &["wss://relay.example"]);
        let mut cache = VerifiedDmRelayCache::new();
        cache.insert(record).expect("store record");
        let encoded = cache.to_json().expect("encode cache");
        assert_eq!(
            VerifiedDmRelayCache::from_json(
                &encoded,
                NOW,
                &EventLimits::default(),
                &DmInboxPolicy::default(),
            )
            .expect("decode cache"),
            cache
        );

        let tampered = String::from_utf8(encoded)
            .expect("JSON text")
            .replace("wss://relay.example", "wss://attacker.example");
        assert_eq!(
            VerifiedDmRelayCache::from_json(
                tampered.as_bytes(),
                NOW,
                &EventLimits::default(),
                &DmInboxPolicy::default(),
            ),
            Err(DmRelayCacheError::InvalidSourceEvent)
        );
        assert!(
            VerifiedDmRelayCache::from_json(
                br#"{"version":1,"records":[],"extra":true}"#,
                NOW,
                &EventLimits::default(),
                &DmInboxPolicy::default(),
            )
            .is_err()
        );
    }
}
