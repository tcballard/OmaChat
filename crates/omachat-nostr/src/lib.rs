//! Nostr transport for direct messages: NIP-01 events, NIP-17/NIP-59 gift wraps,
//! NIP-44 payloads, NIP-65 and NIP-17 relay lists, profiles, and the relay pool.
//!
//! Callers supply an explicit secp256k1 secret (`nostr-identity-v1`). This crate
//! does not derive a key from the device Ed25519 identity.
//!
//! NIP-29 group relay hosting and BLE mesh are not part of this crate.

pub mod auth;
pub mod discovery;
pub mod dm_delivery;
pub mod dm_inbox;
pub mod dm_inbox_runtime;
pub mod dm_relay_cache;
pub mod dm_relay_discovery;
pub mod dm_relay_list;
pub mod dm_relay_routing;
pub mod dm_routed_publish;
pub mod event;
pub mod frame;
pub mod gift_wrap;
pub mod inbox;
pub mod nip05;
pub mod nip11;
pub mod pool;
pub mod profile_cache;
pub mod profile_discovery;
pub mod profile_metadata;
pub mod profile_verification;
pub mod relay;
pub mod relay_list;
pub mod relay_list_cache;
pub mod relay_list_discovery;
mod replaceable_discovery;
