//! Fail-closed master-key selection and sealed atomic records.

mod account;
mod archive;
mod courier;
mod erase;
mod identity;
mod outbox;
mod registry;
mod registry_cache;
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
pub use registry::{RegistryVault, RegistryVaultError};
pub use registry_cache::{
    CachedRegistryRecord, RegistryCacheError, RegistryCacheLookup, VerifiedRegistryCache,
};
pub use sealed::{
    MasterKey, ProviderKind, RequestedProvider, SealedStore, StoreError, StoreStatus,
};
pub use trust::{BlockList, PeerTrust, PeerTrustStore, TrustError};
