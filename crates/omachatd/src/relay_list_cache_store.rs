use std::{error::Error, fmt};

use omachat_nostr::{
    discovery::{RelayDiscoveryLimits, RelayList},
    event::{EventLimits, SignedEvent},
    relay_list_cache::{
        RelayListCacheError, RelayListCacheLookup, RelayListCacheMutation, VerifiedRelayListCache,
    },
};
use omachat_store::{SealedStore, StoreError};

pub const NIP65_RELAY_LIST_CACHE_RECORD_NAME: &str = "nip65-relay-list-cache-v1";

pub struct SealedRelayListCache<'a> {
    store: &'a SealedStore,
}

impl<'a> SealedRelayListCache<'a> {
    pub fn new(store: &'a SealedStore) -> Self {
        Self { store }
    }

    pub fn load(
        &self,
        now: u64,
        event_limits: &EventLimits,
        relay_limits: &RelayDiscoveryLimits,
    ) -> Result<SealedRelayListCacheState, SealedRelayListCacheError> {
        let encoded = match self.store.read(NIP65_RELAY_LIST_CACHE_RECORD_NAME) {
            Ok(encoded) => encoded,
            Err(StoreError::RecordNotFound) => return Ok(SealedRelayListCacheState::Missing),
            Err(error) => return Err(error.into()),
        };
        let cache = VerifiedRelayListCache::from_json(&encoded, now, event_limits, relay_limits)?;
        Ok(SealedRelayListCacheState::Loaded(cache))
    }

    pub fn save(&self, cache: &VerifiedRelayListCache) -> Result<(), SealedRelayListCacheError> {
        let encoded = cache.to_json()?;
        self.store
            .write(NIP65_RELAY_LIST_CACHE_RECORD_NAME, &encoded)?;
        Ok(())
    }

    /// Verify and durably store one exact-author NIP-65 event before exposing
    /// the mutation to callers.
    pub fn verify_and_save(
        &self,
        event: &SignedEvent,
        expected_public_key: &[u8; 32],
        now: u64,
        event_limits: &EventLimits,
        relay_limits: &RelayDiscoveryLimits,
    ) -> Result<RelayListCacheMutation, SealedRelayListCacheError> {
        if event.pubkey != hex::encode(expected_public_key) {
            return Err(SealedRelayListCacheError::UnexpectedAuthor);
        }
        let mut cache = match self.load(now, event_limits, relay_limits)? {
            SealedRelayListCacheState::Missing => VerifiedRelayListCache::new(),
            SealedRelayListCacheState::Loaded(cache) => cache,
        };
        let mutation = cache.insert_event(event.clone(), now, now, event_limits, relay_limits)?;
        if mutation == RelayListCacheMutation::Stored {
            self.save(&cache)?;
        }
        Ok(mutation)
    }

    pub fn lookup(
        &self,
        public_key: &[u8; 32],
        now: u64,
        freshness_window_seconds: u64,
        event_limits: &EventLimits,
        relay_limits: &RelayDiscoveryLimits,
    ) -> Result<SealedRelayListCacheLookup, SealedRelayListCacheError> {
        let cache = match self.load(now, event_limits, relay_limits)? {
            SealedRelayListCacheState::Missing => return Ok(SealedRelayListCacheLookup::Missing),
            SealedRelayListCacheState::Loaded(cache) => cache,
        };
        Ok(
            match cache.lookup(public_key, now, freshness_window_seconds) {
                RelayListCacheLookup::Missing => SealedRelayListCacheLookup::Missing,
                RelayListCacheLookup::Fresh(record) => {
                    SealedRelayListCacheLookup::Fresh(record.relay_list().clone())
                }
                RelayListCacheLookup::OfflineStale(record) => {
                    SealedRelayListCacheLookup::OfflineStale(record.relay_list().clone())
                }
                RelayListCacheLookup::UnusableClockRollback(record) => {
                    SealedRelayListCacheLookup::UnusableClockRollback(record.relay_list().clone())
                }
            },
        )
    }

    pub fn clear(&self) -> Result<(), SealedRelayListCacheError> {
        self.store.delete(NIP65_RELAY_LIST_CACHE_RECORD_NAME)?;
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SealedRelayListCacheState {
    Missing,
    Loaded(VerifiedRelayListCache),
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SealedRelayListCacheLookup {
    Missing,
    Fresh(RelayList),
    OfflineStale(RelayList),
    UnusableClockRollback(RelayList),
}

#[derive(Debug)]
pub enum SealedRelayListCacheError {
    Store(StoreError),
    Cache(RelayListCacheError),
    UnexpectedAuthor,
}

impl fmt::Display for SealedRelayListCacheError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Store(error) => write!(formatter, "sealed NIP-65 storage failed: {error}"),
            Self::Cache(error) => write!(formatter, "NIP-65 cache validation failed: {error}"),
            Self::UnexpectedAuthor => {
                formatter.write_str("NIP-65 event author does not match the requested participant")
            }
        }
    }
}

impl Error for SealedRelayListCacheError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Store(error) => Some(error),
            Self::Cache(error) => Some(error),
            Self::UnexpectedAuthor => None,
        }
    }
}

impl From<StoreError> for SealedRelayListCacheError {
    fn from(error: StoreError) -> Self {
        Self::Store(error)
    }
}

impl From<RelayListCacheError> for SealedRelayListCacheError {
    fn from(error: RelayListCacheError) -> Self {
        Self::Cache(error)
    }
}
