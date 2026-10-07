//! Sealed local credentials and chat state.
mod erase;
mod identity;
mod sealed;
pub use erase::PanicEraseReport;
pub use identity::{IdentityStoreError, IdentityVault};
pub use sealed::{
    MasterKey, ProviderKind, RequestedProvider, SealedStore, StoreError, StoreStatus,
};
