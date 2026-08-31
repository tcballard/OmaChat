//! Fail-closed master-key selection and sealed atomic records.

mod archive;
mod identity;
mod outbox;
mod sealed;
mod trust;

pub use archive::{ArchiveError, PublicArchive, PublicArchiveEntry, TransientPublicCaches};
pub use identity::{IdentityStoreError, IdentityVault};
pub use outbox::{
    AttemptOutcome, NostrOutbox, OutboxError, OutboxMessage, OutboxState, OutboxTransport,
    TransportAttempt,
};
pub use sealed::{
    MasterKey, ProviderKind, RequestedProvider, SealedStore, StoreError, StoreStatus,
};
pub use trust::{BlockList, PeerTrust, PeerTrustStore, TrustError};
