use std::{error::Error, fmt};

use omachat_nostr::{
    auth::RelayAuthSigner,
    discovery::{RelayDiscoveryLimits, RelayList},
    event::{EventLimits, SignedEvent},
    relay::RelayConfig,
    relay_list_cache::{RelayListCacheMutation, VerifiedRelayListCache},
    relay_list_discovery::{
        RelayListDiscoveryConfig, RelayListDiscoveryError, discover_nip65_relay_list,
    },
};
use omachat_store::SealedStore;

use crate::{SealedRelayListCache, SealedRelayListCacheError, SealedRelayListCacheState};

pub struct SealedRelayListDiscoveryService<'a> {
    cache: SealedRelayListCache<'a>,
    event_limits: EventLimits,
    relay_limits: RelayDiscoveryLimits,
    discovery_config: RelayListDiscoveryConfig,
}

impl<'a> SealedRelayListDiscoveryService<'a> {
    pub fn new(
        store: &'a SealedStore,
        event_limits: EventLimits,
        relay_limits: RelayDiscoveryLimits,
        discovery_config: RelayListDiscoveryConfig,
    ) -> Self {
        Self {
            cache: SealedRelayListCache::new(store),
            event_limits,
            relay_limits,
            discovery_config,
        }
    }

    pub async fn discover_and_save(
        &self,
        relay_configs: Vec<RelayConfig>,
        auth_signer: RelayAuthSigner,
        participant_public_key: &[u8; 32],
        now: u64,
    ) -> Result<SealedRelayListDiscoveryResult, SealedRelayListDiscoveryServiceError> {
        let discovered = discover_nip65_relay_list(
            relay_configs,
            auth_signer,
            participant_public_key,
            now,
            &self.event_limits,
            &self.relay_limits,
            &self.discovery_config,
        )
        .await?;
        let mutation = self.cache.verify_and_save(
            &discovered.event,
            participant_public_key,
            now,
            &self.event_limits,
            &self.relay_limits,
        )?;
        Ok(SealedRelayListDiscoveryResult {
            event: discovered.event,
            relay_list: discovered.relay_list,
            mutation,
            queried_relays: discovered.queried_relays,
            completed_relays: discovered.completed_relays,
        })
    }

    pub fn load_cache(
        &self,
        now: u64,
    ) -> Result<SealedRelayListCacheState, SealedRelayListDiscoveryServiceError> {
        self.cache
            .load(now, &self.event_limits, &self.relay_limits)
            .map_err(Into::into)
    }

    pub fn save_cache(
        &self,
        cache: &VerifiedRelayListCache,
    ) -> Result<(), SealedRelayListDiscoveryServiceError> {
        self.cache.save(cache).map_err(Into::into)
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SealedRelayListDiscoveryResult {
    pub event: SignedEvent,
    pub relay_list: RelayList,
    pub mutation: RelayListCacheMutation,
    pub queried_relays: usize,
    pub completed_relays: usize,
}

#[derive(Debug)]
pub enum SealedRelayListDiscoveryServiceError {
    Discovery(RelayListDiscoveryError),
    Storage(SealedRelayListCacheError),
}

impl fmt::Display for SealedRelayListDiscoveryServiceError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Discovery(error) => write!(formatter, "relay-list discovery failed: {error}"),
            Self::Storage(error) => write!(formatter, "relay-list persistence failed: {error}"),
        }
    }
}

impl Error for SealedRelayListDiscoveryServiceError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Discovery(error) => Some(error),
            Self::Storage(error) => Some(error),
        }
    }
}

impl From<RelayListDiscoveryError> for SealedRelayListDiscoveryServiceError {
    fn from(error: RelayListDiscoveryError) -> Self {
        Self::Discovery(error)
    }
}

impl From<SealedRelayListCacheError> for SealedRelayListDiscoveryServiceError {
    fn from(error: SealedRelayListCacheError) -> Self {
        Self::Storage(error)
    }
}
