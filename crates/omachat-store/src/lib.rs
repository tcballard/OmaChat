//! Sealed local credentials and chat state.
mod erase;
mod identity;
mod nostr;
mod sealed;
pub use erase::PanicEraseReport;
pub use identity::{IdentityStoreError, IdentityVault};
pub use nostr::{NostrStoreError, NostrVault};
pub use sealed::{
    MasterKey, ProviderKind, RequestedProvider, SealedStore, StoreError, StoreStatus,
};
