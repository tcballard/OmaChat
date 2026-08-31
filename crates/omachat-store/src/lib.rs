//! Fail-closed master-key selection and sealed atomic records.

mod identity;
mod outbox;
mod sealed;

pub use identity::{IdentityStoreError, IdentityVault};
pub use outbox::{
    AttemptOutcome, NostrOutbox, OutboxError, OutboxMessage, OutboxState, OutboxTransport,
    TransportAttempt,
};
pub use sealed::{
    MasterKey, ProviderKind, RequestedProvider, SealedStore, StoreError, StoreStatus,
};
