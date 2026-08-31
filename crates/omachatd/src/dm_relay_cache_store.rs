use std::error::Error;
use std::fmt;

use omachat_nostr::{
    dm_relay_cache::{DmRelayCacheError, VerifiedDmRelayCache},
    event::EventLimits,
    inbox::DmInboxPolicy,
};
use omachat_store::{SealedStore, StoreError};

pub const DM_RELAY_CACHE_RECORD_NAME: &str = "dm-relay-cache-v1";

pub struct SealedDmRelayCache<'a> {
    store: &'a SealedStore,
}

impl<'a> SealedDmRelayCache<'a> {
    pub fn new(store: &'a SealedStore) -> Self {
        Self { store }
    }

    pub fn load(
        &self,
        now: u64,
        event_limits: &EventLimits,
        policy: &DmInboxPolicy,
    ) -> Result<SealedDmRelayCacheState, SealedDmRelayCacheError> {
        let encoded = match self.store.read(DM_RELAY_CACHE_RECORD_NAME) {
            Ok(encoded) => encoded,
            Err(StoreError::RecordNotFound) => return Ok(SealedDmRelayCacheState::Missing),
            Err(error) => return Err(error.into()),
        };
        let cache = VerifiedDmRelayCache::from_json(&encoded, now, event_limits, policy)?;
        Ok(SealedDmRelayCacheState::Loaded(cache))
    }

    pub fn save(&self, cache: &VerifiedDmRelayCache) -> Result<(), SealedDmRelayCacheError> {
        let encoded = cache.to_json()?;
        self.store.write(DM_RELAY_CACHE_RECORD_NAME, &encoded)?;
        Ok(())
    }

    pub fn clear(&self) -> Result<(), SealedDmRelayCacheError> {
        self.store.delete(DM_RELAY_CACHE_RECORD_NAME)?;
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SealedDmRelayCacheState {
    Missing,
    Loaded(VerifiedDmRelayCache),
}

#[derive(Debug)]
pub enum SealedDmRelayCacheError {
    Store(StoreError),
    Cache(DmRelayCacheError),
}

impl fmt::Display for SealedDmRelayCacheError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Store(error) => {
                write!(formatter, "sealed DM relay cache storage failed: {error}")
            }
            Self::Cache(error) => write!(
                formatter,
                "sealed DM relay cache validation failed: {error}"
            ),
        }
    }
}

impl Error for SealedDmRelayCacheError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Store(error) => Some(error),
            Self::Cache(error) => Some(error),
        }
    }
}

impl From<StoreError> for SealedDmRelayCacheError {
    fn from(error: StoreError) -> Self {
        Self::Store(error)
    }
}

impl From<DmRelayCacheError> for SealedDmRelayCacheError {
    fn from(error: DmRelayCacheError) -> Self {
        Self::Cache(error)
    }
}
