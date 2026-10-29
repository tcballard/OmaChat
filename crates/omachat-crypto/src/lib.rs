//! Device authentication, account names, optional Nostr identity, and NIP-44.
mod account;
mod identity;
mod nip44;
mod nostr;
pub use account::{AccountError, DisplayName, GlobalHandle};
pub use identity::{IdentityError, IdentitySecrets, PublicIdentity};
pub use nip44::{
    MAX_PLAINTEXT_LEN as NIP44_MAX_PLAINTEXT_LEN, Nip44Error,
    conversation_key as nip44_conversation_key, decrypt as nip44_decrypt, encrypt as nip44_encrypt,
    encrypt_with_nonce as nip44_encrypt_with_nonce,
};
pub use nostr::{
    NostrIdentityError, NostrSecret, nostr_public_key_hex, npub_from_public_key,
    public_key_from_npub, verify_nostr,
};
