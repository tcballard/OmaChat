//! Fail-closed master-key selection and sealed atomic records.

mod account;
mod archive;
mod courier;
mod erase;
mod identity;
mod outbox;
mod principal_registry;
mod principal_registry_cache;
mod principal_registry_claim_intent;
mod registry;
mod registry_cache;
mod registry_claim_intent;
mod sealed;
mod trust;

pub use account::{AccountVault, AccountVaultError, LocalAccount};
pub use archive::{ArchiveError, PublicArchive, PublicArchiveEntry, TransientPublicCaches};
pub use courier::{CourierPool, CourierPoolError, CourierTier, Handover, StoredCourier};
pub use erase::PanicEraseReport;
pub use identity::{IdentityStoreError, IdentityVault};
pub use outbox::{
    AttemptOutcome, NostrDeliveryProfile, NostrOutbox, OutboxError, OutboxMessage, OutboxState,
    OutboxTransport, TransportAttempt,
};
pub use principal_registry::{PrincipalRegistryVault, PrincipalRegistryVaultError};
pub use principal_registry_cache::{
    CachedPrincipalRegistryRecord, PrincipalRegistryCacheError, PrincipalRegistryCacheLookup,
    PrincipalRegistryEvidence, VerifiedPrincipalRegistryCache,
};
pub use principal_registry_claim_intent::{
    PRINCIPAL_REGISTRY_CLAIM_INTENT_RECORD_NAME, PrincipalRegistryClaimIntentError,
    PrincipalRegistryClaimIntentStore,
};
pub use registry::{RegistryVault, RegistryVaultError};
pub use registry_cache::{
    CachedRegistryRecord, RegistryCacheError, RegistryCacheLookup, VerifiedRegistryCache,
};
pub use registry_claim_intent::{
    REGISTRY_CLAIM_INTENT_RECORD_NAME, RegistryClaimIntentError, RegistryClaimIntentStore,
};
pub use sealed::{
    MasterKey, ProviderKind, RequestedProvider, SealedStore, StoreError, StoreStatus,
};
pub use trust::{BlockList, PeerTrust, PeerTrustStore, TrustError};
