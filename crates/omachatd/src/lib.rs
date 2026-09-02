//! Headless daemon IPC service primitives.

mod agent_lifecycle_store;
mod config;
mod core;
mod core_error;
mod dm_delivery_service;
mod dm_inbox_service;
mod dm_relay_cache_store;
mod ipc_server;
mod nostr_service;
mod principal_registry_evidence_service;
mod profile_cache_store;
mod profile_publication_coordinator;
mod profile_publication_service;
mod profile_publication_store;
mod registry_evidence_service;
mod relay_list_cache_store;
mod relay_list_discovery_service;
mod relay_list_nostr_publisher;
mod relay_list_publication_coordinator;
mod relay_list_publication_runtime;
mod relay_list_publication_store;

pub use agent_lifecycle_store::{
    AGENT_LIFECYCLE_RECORD_NAME, SealedAgentLifecycle, SealedAgentLifecycleError,
    SealedAgentLifecycleState,
};
pub use config::{
    DaemonConfig, ProfilePublicationConfig, RegistryClientConfig, RegistryProtocol,
    RelayListPublicationConfig, RelayListPublicationRelayConfig, StorageProviderConfig,
};
pub use core::{
    DaemonCore, PanicState, RegistryClaimEvidence, RegistryClaimResult, RegistryClaimStatus,
};
pub use core_error::CoreError;
pub use dm_delivery_service::{
    DmDeliveryHandle, DmDeliveryService, DmDeliveryServiceConfig, DmDeliveryServiceError,
};
pub use dm_inbox_service::{DmInboxHandle, DmInboxService, DmInboxServiceError};
pub use dm_relay_cache_store::{
    DM_RELAY_CACHE_RECORD_NAME, SealedDmRelayCache, SealedDmRelayCacheError,
    SealedDmRelayCacheState,
};
pub use ipc_server::{EventHub, IpcServer, RequestHandler, ServerError};
pub use nostr_service::{NostrHandle, NostrService};
pub use principal_registry_evidence_service::PrincipalRegistryEvidenceService;
pub use profile_cache_store::{
    PROFILE_CACHE_RECORD_NAME, SealedProfileCache, SealedProfileCacheError,
    SealedProfileCacheLookup, SealedProfileCacheState,
};
pub use profile_publication_coordinator::{
    ProfilePublicationCoordinator, ProfilePublicationCoordinatorError,
    ProfilePublicationCoordinatorHandle, ProfilePublicationOutcome,
    ProfilePublicationOutcomeStatus,
};
pub use profile_publication_service::{
    ProfilePublicationHandle, ProfilePublicationService, ProfilePublicationServiceConfig,
    ProfilePublicationServiceError,
};
pub use profile_publication_store::{
    MAX_PROFILE_PUBLICATION_RELAYS, PROFILE_PUBLICATION_INTENT_RECORD_NAME,
    PendingProfilePublication, ProfilePublicationIntentError, ProfilePublicationIntentStore,
    ProfilePublicationProgress,
};
pub use registry_evidence_service::RegistryEvidenceService;
pub use relay_list_cache_store::{
    NIP65_RELAY_LIST_CACHE_RECORD_NAME, SealedRelayListCache, SealedRelayListCacheError,
    SealedRelayListCacheLookup, SealedRelayListCacheState,
};
pub use relay_list_discovery_service::{
    SealedRelayListDiscoveryResult, SealedRelayListDiscoveryService,
    SealedRelayListDiscoveryServiceError,
};
pub use relay_list_nostr_publisher::{
    NostrRelayListPublisherConfig, NostrRelayListPublisherError, NostrRelayListPublisherHandle,
    NostrRelayListPublisherService,
};
pub use relay_list_publication_coordinator::{
    RelayListPublicationCoordinator, RelayListPublicationCoordinatorError,
    RelayListPublicationOutcome, RelayListPublicationOutcomeStatus, RelayListPublicationSource,
    RelayListPublishFuture, RelayListPublisher, RelayListRelayResult, RelayListRelayStatus,
};
pub use relay_list_publication_runtime::{
    RelayListPublicationRuntime, RelayListPublicationRuntimeError,
};
pub use relay_list_publication_store::{
    PendingRelayListPublication, RELAY_LIST_PUBLICATION_INTENT_RECORD_NAME,
    RelayListPublicationIntentError, RelayListPublicationIntentState,
    RelayListPublicationIntentStore, RelayListPublicationMutation, RelayListPublicationProgress,
};
