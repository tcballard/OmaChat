use std::error::Error;
use std::fmt;

use omachat_nostr::{
    dm_relay_cache::{CacheMutation, DmRelayCacheError, VerifiedDmRelayCache},
    dm_relay_routing::{DmRelayRoute, DmRelayRoutingError, DmRelayRoutingPolicy, route_dm_relays},
    event::{EventLimits, SignedEvent},
    inbox::{DmInboxError, DmInboxPolicy, verify_dm_inbox},
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

    /// Verify and durably store recipient-authored kind 10050 metadata before
    /// exposing the mutation to callers.
    pub fn verify_and_save(
        &self,
        event: &SignedEvent,
        expected_recipient_public_key: &[u8; 32],
        now: u64,
        event_limits: &EventLimits,
        policy: &DmInboxPolicy,
    ) -> Result<CacheMutation, SealedDmRelayCacheError> {
        let verified = verify_dm_inbox(
            event,
            expected_recipient_public_key,
            now,
            event_limits,
            policy,
        )?;
        let mut cache = match self.load(now, event_limits, policy)? {
            SealedDmRelayCacheState::Missing => VerifiedDmRelayCache::new(),
            SealedDmRelayCacheState::Loaded(cache) => cache,
        };
        let mutation = cache.insert(verified.to_cache_record(now)?)?;
        if mutation == CacheMutation::Stored {
            self.save(&cache)?;
        }
        Ok(mutation)
    }

    /// Resolve one recipient route from cryptographically revalidated sealed
    /// state. Bootstrap fallback remains an explicit caller policy.
    pub fn route(
        &self,
        recipient_public_key: &[u8; 32],
        now: u64,
        bootstrap_relays: &[String],
        routing_policy: DmRelayRoutingPolicy,
        event_limits: &EventLimits,
        inbox_policy: &DmInboxPolicy,
    ) -> Result<DmRelayRoute, SealedDmRelayCacheError> {
        let cache = match self.load(now, event_limits, inbox_policy)? {
            SealedDmRelayCacheState::Missing => VerifiedDmRelayCache::new(),
            SealedDmRelayCacheState::Loaded(cache) => cache,
        };
        Ok(route_dm_relays(
            &cache,
            recipient_public_key,
            now,
            bootstrap_relays,
            routing_policy,
        )?)
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
    Inbox(DmInboxError),
    Routing(DmRelayRoutingError),
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
            Self::Inbox(error) => {
                write!(formatter, "DM relay metadata verification failed: {error}")
            }
            Self::Routing(error) => write!(formatter, "DM relay routing failed: {error}"),
        }
    }
}

impl Error for SealedDmRelayCacheError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Store(error) => Some(error),
            Self::Cache(error) => Some(error),
            Self::Inbox(error) => Some(error),
            Self::Routing(error) => Some(error),
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

impl From<DmInboxError> for SealedDmRelayCacheError {
    fn from(error: DmInboxError) -> Self {
        Self::Inbox(error)
    }
}

impl From<DmRelayRoutingError> for SealedDmRelayCacheError {
    fn from(error: DmRelayRoutingError) -> Self {
        Self::Routing(error)
    }
}
