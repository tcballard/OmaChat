//! Device authentication and account name validation.
mod account;
mod identity;
pub use account::{AccountError, DisplayName, GlobalHandle};
pub use identity::{IdentityError, IdentitySecrets, PublicIdentity};
