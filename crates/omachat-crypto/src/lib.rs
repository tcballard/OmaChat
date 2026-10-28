//! Device authentication, account names and optional Nostr identity.
mod account;
mod identity;
mod nostr;
pub use account::{AccountError, DisplayName, GlobalHandle};
pub use identity::{IdentityError, IdentitySecrets, PublicIdentity};
pub use nostr::{
    NostrIdentityError, NostrSecret, nostr_public_key_hex, npub_from_public_key,
    public_key_from_npub, verify_nostr,
};
