use std::error::Error;
use std::fmt;

use omachat_nostr::{
    event::EventLimits,
    profile_cache::{ProfileCacheError, VerifiedProfileCache},
};
use omachat_store::{SealedStore, StoreError};

pub const PROFILE_CACHE_RECORD_NAME: &str = "profile-cache-v1";

pub struct SealedProfileCache<'a> {
    store: &'a SealedStore,
}

impl<'a> SealedProfileCache<'a> {
    pub fn new(store: &'a SealedStore) -> Self {
        Self { store }
    }

    pub fn load(
        &self,
        now: u64,
        event_limits: &EventLimits,
    ) -> Result<SealedProfileCacheState, SealedProfileCacheError> {
        let encoded = match self.store.read(PROFILE_CACHE_RECORD_NAME) {
            Ok(encoded) => encoded,
            Err(StoreError::RecordNotFound) => return Ok(SealedProfileCacheState::Missing),
            Err(error) => return Err(error.into()),
        };
        let cache = VerifiedProfileCache::from_json(&encoded, now, event_limits)?;
        Ok(SealedProfileCacheState::Loaded(cache))
    }

    pub fn save(&self, cache: &VerifiedProfileCache) -> Result<(), SealedProfileCacheError> {
        let encoded = cache.to_json()?;
        self.store.write(PROFILE_CACHE_RECORD_NAME, &encoded)?;
        Ok(())
    }

    pub fn clear(&self) -> Result<(), SealedProfileCacheError> {
        self.store.delete(PROFILE_CACHE_RECORD_NAME)?;
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SealedProfileCacheState {
    Missing,
    Loaded(VerifiedProfileCache),
}

#[derive(Debug)]
pub enum SealedProfileCacheError {
    Store(StoreError),
    Cache(ProfileCacheError),
}

impl fmt::Display for SealedProfileCacheError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Store(error) => write!(formatter, "sealed profile storage failed: {error}"),
            Self::Cache(error) => write!(formatter, "profile cache validation failed: {error}"),
        }
    }
}

impl Error for SealedProfileCacheError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Store(error) => Some(error),
            Self::Cache(error) => Some(error),
        }
    }
}

impl From<StoreError> for SealedProfileCacheError {
    fn from(error: StoreError) -> Self {
        Self::Store(error)
    }
}

impl From<ProfileCacheError> for SealedProfileCacheError {
    fn from(error: ProfileCacheError) -> Self {
        Self::Cache(error)
    }
}
