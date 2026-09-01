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
mod profile_publication_service;
mod profile_publication_store;
mod registry_evidence_service;

pub use agent_lifecycle_store::{
    AGENT_LIFECYCLE_RECORD_NAME, SealedAgentLifecycle, SealedAgentLifecycleError,
    SealedAgentLifecycleState,
};
pub use config::{DaemonConfig, RegistryClientConfig, RegistryProtocol, StorageProviderConfig};
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
