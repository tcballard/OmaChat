//! Persistence-agnostic verified NIP-65 cache state.

use std::{
    collections::{BTreeMap, BTreeSet},
    error::Error,
    fmt,
};

use serde::{Deserialize, Serialize};

use crate::{
    discovery::{RelayDiscoveryLimits, RelayList, parse_nip65_relay_list},
    event::{EventLimits, SignedEvent},
};

pub const MAX_CACHED_RELAY_LISTS: usize = 4_096;
pub const DEFAULT_RELAY_LIST_FRESHNESS_SECONDS: u64 = 24 * 60 * 60;
const MAX_SERIALIZED_RELAY_LIST_CACHE_BYTES: usize = 1_048_576;
const RELAY_LIST_CACHE_VERSION: u16 = 1;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VerifiedRelayListCacheRecord {
    relay_list: RelayList,
    source_event: SignedEvent,
    verified_at: u64,
}

impl VerifiedRelayListCacheRecord {
    pub fn relay_list(&self) -> &RelayList {
        &self.relay_list
    }

    pub fn source_event(&self) -> &SignedEvent {
        &self.source_event
    }

    pub fn verified_at(&self) -> u64 {
        self.verified_at
    }
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct VerifiedRelayListCache {
    records: BTreeMap<String, VerifiedRelayListCacheRecord>,
}

impl VerifiedRelayListCache {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn len(&self) -> usize {
        self.records.len()
    }

    pub fn is_empty(&self) -> bool {
        self.records.is_empty()
    }

    pub fn insert_event(
        &mut self,
        source_event: SignedEvent,
        now: u64,
        verified_at: u64,
        event_limits: &EventLimits,
        relay_limits: &RelayDiscoveryLimits,
    ) -> Result<RelayListCacheMutation, RelayListCacheError> {
        if verified_at > now || verified_at < source_event.created_at {
            return Err(RelayListCacheError::InvalidVerificationTime);
        }
        let relay_list = parse_nip65_relay_list(&source_event, now, event_limits, relay_limits)
            .map_err(|_| RelayListCacheError::InvalidSourceEvent)?;
        let key = relay_list.public_key.clone();
        if let Some(current) = self.records.get(&key) {
            if source_event.created_at < current.source_event.created_at {
                return Err(RelayListCacheError::Rollback);
            }
            if source_event.created_at == current.source_event.created_at {
                if source_event.id >= current.source_event.id {
                    return Ok(RelayListCacheMutation::Unchanged);
                }
            }
        } else if self.records.len() >= MAX_CACHED_RELAY_LISTS {
            return Err(RelayListCacheError::CacheFull);
        }

        let previous = self.records.insert(
            key.clone(),
            VerifiedRelayListCacheRecord {
                relay_list,
                source_event,
                verified_at,
            },
        );
        if let Err(error) = self.to_json() {
            if let Some(previous) = previous {
                self.records.insert(key, previous);
            } else {
                self.records.remove(&key);
            }
            return Err(error);
        }
        Ok(RelayListCacheMutation::Stored)
    }

    pub fn lookup(
        &self,
        public_key: &[u8; 32],
        now: u64,
        freshness_window_seconds: u64,
    ) -> RelayListCacheLookup<'_> {
        let key = hex::encode(public_key);
        let Some(record) = self.records.get(&key) else {
            return RelayListCacheLookup::Missing;
        };
        let Some(age) = now.checked_sub(record.source_event.created_at) else {
            return RelayListCacheLookup::UnusableClockRollback(record);
        };
        if age <= freshness_window_seconds {
            RelayListCacheLookup::Fresh(record)
        } else {
            RelayListCacheLookup::OfflineStale(record)
        }
    }

    pub fn to_json(&self) -> Result<Vec<u8>, RelayListCacheError> {
        let persisted = PersistedRelayListCache {
            version: RELAY_LIST_CACHE_VERSION,
            records: self
                .records
                .values()
                .map(|record| PersistedRelayListCacheRecord {
                    verified_at: record.verified_at,
                    source_event: record.source_event.clone(),
                })
                .collect(),
        };
        let encoded =
            serde_json::to_vec(&persisted).map_err(|_| RelayListCacheError::InvalidEncoding)?;
        if encoded.len() > MAX_SERIALIZED_RELAY_LIST_CACHE_BYTES {
            return Err(RelayListCacheError::CacheTooLarge);
        }
        Ok(encoded)
    }

    pub fn from_json(
        encoded: &[u8],
        now: u64,
        event_limits: &EventLimits,
        relay_limits: &RelayDiscoveryLimits,
    ) -> Result<Self, RelayListCacheError> {
        if encoded.len() > MAX_SERIALIZED_RELAY_LIST_CACHE_BYTES {
            return Err(RelayListCacheError::CacheTooLarge);
        }
        let persisted: PersistedRelayListCache =
            serde_json::from_slice(encoded).map_err(|_| RelayListCacheError::InvalidEncoding)?;
        if persisted.version != RELAY_LIST_CACHE_VERSION {
            return Err(RelayListCacheError::UnsupportedVersion(persisted.version));
        }
        if persisted.records.len() > MAX_CACHED_RELAY_LISTS {
            return Err(RelayListCacheError::CacheFull);
        }

        let mut seen = BTreeSet::new();
        let mut cache = Self::new();
        for record in persisted.records {
            if record.verified_at > now {
                return Err(RelayListCacheError::InvalidVerificationTime);
            }
            let mut public_key = [0; 32];
            hex::decode_to_slice(&record.source_event.pubkey, &mut public_key)
                .map_err(|_| RelayListCacheError::InvalidSourceEvent)?;
            if !seen.insert(public_key) {
                return Err(RelayListCacheError::InvalidEncoding);
            }
            cache.insert_event(
                record.source_event,
                now,
                record.verified_at,
                event_limits,
                relay_limits,
            )?;
        }
        Ok(cache)
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct PersistedRelayListCache {
    version: u16,
    records: Vec<PersistedRelayListCacheRecord>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct PersistedRelayListCacheRecord {
    verified_at: u64,
    source_event: SignedEvent,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RelayListCacheMutation {
    Stored,
    Unchanged,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RelayListCacheLookup<'a> {
    Missing,
    Fresh(&'a VerifiedRelayListCacheRecord),
    OfflineStale(&'a VerifiedRelayListCacheRecord),
    UnusableClockRollback(&'a VerifiedRelayListCacheRecord),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RelayListCacheError {
    InvalidVerificationTime,
    InvalidSourceEvent,
    InvalidEncoding,
    UnsupportedVersion(u16),
    Rollback,
    CacheFull,
    CacheTooLarge,
}

impl fmt::Display for RelayListCacheError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidVerificationTime => {
                formatter.write_str("invalid relay-list verification time")
            }
            Self::InvalidSourceEvent => formatter.write_str("invalid signed NIP-65 source event"),
            Self::InvalidEncoding => formatter.write_str("invalid relay-list cache encoding"),
            Self::UnsupportedVersion(version) => {
                write!(formatter, "unsupported relay-list cache version {version}")
            }
            Self::Rollback => {
                formatter.write_str("older relay metadata cannot replace newer state")
            }
            Self::CacheFull => formatter.write_str("relay-list cache is full"),
            Self::CacheTooLarge => {
                formatter.write_str("serialized relay-list cache exceeds its bound")
            }
        }
    }
}

impl Error for RelayListCacheError {}
