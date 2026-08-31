//! Fail-closed master-key selection and sealed atomic records.

mod identity;
mod sealed;

pub use identity::{IdentityStoreError, IdentityVault};
pub use sealed::{
    MasterKey, ProviderKind, RequestedProvider, SealedStore, StoreError, StoreStatus,
};
