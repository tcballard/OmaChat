//! Crash-safe sealed persistence for one relay's NIP-29 room state.
//!
//! Each relay identity gets one sealed record holding the room-state snapshot.
//! Its generation is checked against a caller-supplied anchor that MUST live
//! outside the sealed store's rollback domain.
//!
//! Generation zero is anchored before the first state write. Each later state
//! record is written before advancing the external anchor. A crash between
//! those operations leaves the authenticated record one generation ahead and
//! is healed on load. A record behind the anchor, a missing anchor beside a
//! record, or a missing record after generation zero fails closed.

use crate::{SealedStore, StoreError};
use omachat_nostr::{
    event::EventLimits,
    nip29_room_state::{RelayRoomState, RelayRoomStateSnapshot, RoomStateError},
};
use serde::{Deserialize, Serialize};
use std::{error::Error, fmt};

pub const ROOM_STATE_RECORD_VERSION: u16 = 1;
const RECORD_PREFIX: &str = "nip29-rooms-v1-";
const MAX_ROOM_STATE_PLAINTEXT_BYTES: usize = 4 * 1024 * 1024;
const MAX_CONTEXT_BYTES: usize = 128;

#[derive(Deserialize, Serialize)]
struct SealedRoomStateRecord {
    record_version: u16,
    store_context: String,
    relay_pubkey: String,
    generation: u64,
    snapshot: RelayRoomStateSnapshot,
}

/// Read first so a future schema is reported as unsupported, not malformed.
#[derive(Deserialize)]
struct RecordHeader {
    record_version: u16,
}

/// Monotonic generation storage outside the sealed room-state rollback domain.
///
/// Implementations must ensure a previously stored generation cannot be
/// deleted or lowered by restoring the [`SealedStore`] from backup.
pub trait RoomStateGenerationAnchor: Send + Sync {
    fn load_generation(
        &self,
        store_context: &str,
        relay_pubkey: &str,
    ) -> Result<Option<u64>, RoomStateAnchorError>;

    fn store_generation(
        &self,
        store_context: &str,
        relay_pubkey: &str,
        generation: u64,
    ) -> Result<(), RoomStateAnchorError>;
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RoomStateAnchorError {
    message: String,
}

impl RoomStateAnchorError {
    #[must_use]
    pub fn new(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
        }
    }
}

impl fmt::Display for RoomStateAnchorError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.message)
    }
}

impl Error for RoomStateAnchorError {}

/// What a load found before the state itself was restored.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RoomStateLoad {
    /// Neither record nor marker existed: a legitimately empty store.
    Fresh,
    /// A persisted record was authenticated, validated, and restored.
    Restored { generation: u64 },
}

/// Persistence boundary for one relay's room state.
pub struct RoomStateVault<'store> {
    store: &'store SealedStore,
    anchor: &'store dyn RoomStateGenerationAnchor,
    store_context: String,
    relay_pubkey: String,
    record_name: String,
    generation: u64,
}

impl<'store> RoomStateVault<'store> {
    /// Bind a vault to a store, a caller-chosen store context (for example
    /// the local account or device public key), and one relay identity.
    pub fn open(
        store: &'store SealedStore,
        anchor: &'store dyn RoomStateGenerationAnchor,
        store_context: &str,
        relay_pubkey: &str,
    ) -> Result<Self, RoomStateVaultError> {
        if store_context.is_empty() || store_context.len() > MAX_CONTEXT_BYTES {
            return Err(RoomStateVaultError::InvalidContext);
        }
        if relay_pubkey.len() != 64
            || !relay_pubkey
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        {
            return Err(RoomStateVaultError::InvalidRelayPublicKey);
        }
        let record_name = format!("{RECORD_PREFIX}{relay_pubkey}");
        Ok(Self {
            store,
            anchor,
            store_context: store_context.to_owned(),
            relay_pubkey: relay_pubkey.to_owned(),
            record_name,
            generation: 0,
        })
    }

    #[must_use]
    pub fn relay_pubkey(&self) -> &str {
        &self.relay_pubkey
    }

    /// Generation of the last state loaded or persisted through this vault.
    #[must_use]
    pub const fn generation(&self) -> u64 {
        self.generation
    }

    /// Load and validate the persisted room state, returning an empty state
    /// only when the store provably never held one for this relay.
    pub fn load_or_create(
        &mut self,
        now: u64,
        limits: &EventLimits,
    ) -> Result<(RelayRoomState, RoomStateLoad), RoomStateVaultError> {
        let anchor = self
            .anchor
            .load_generation(&self.store_context, &self.relay_pubkey)
            .map_err(RoomStateVaultError::Anchor)?;
        let record = match self.store.read(&self.record_name) {
            Ok(bytes) => Some(bytes),
            Err(StoreError::RecordNotFound) => None,
            Err(error) => return Err(RoomStateVaultError::Store(error)),
        };

        let Some(record) = record else {
            return match anchor {
                None | Some(0) => {
                    if anchor.is_none() {
                        self.anchor
                            .store_generation(&self.store_context, &self.relay_pubkey, 0)
                            .map_err(RoomStateVaultError::Anchor)?;
                    }
                    self.generation = 0;
                    Ok((
                        RelayRoomState::new(self.relay_pubkey.clone())
                            .map_err(RoomStateVaultError::Corrupt)?,
                        RoomStateLoad::Fresh,
                    ))
                }
                Some(anchor_generation) => Err(RoomStateVaultError::Rollback {
                    record_generation: 0,
                    anchor_generation,
                }),
            };
        };

        let Some(anchor_generation) = anchor else {
            return Err(RoomStateVaultError::MissingAnchor);
        };

        let header: RecordHeader =
            serde_json::from_slice(&record).map_err(|_| RoomStateVaultError::Encoding)?;
        if header.record_version != ROOM_STATE_RECORD_VERSION {
            return Err(RoomStateVaultError::UnsupportedVersion(
                header.record_version,
            ));
        }
        let decoded: SealedRoomStateRecord =
            serde_json::from_slice(&record).map_err(|_| RoomStateVaultError::Encoding)?;
        if decoded.store_context != self.store_context {
            return Err(RoomStateVaultError::ContextMismatch);
        }
        if decoded.relay_pubkey != self.relay_pubkey
            || decoded.snapshot.relay_pubkey() != self.relay_pubkey
        {
            return Err(RoomStateVaultError::RelayMismatch);
        }
        if decoded.generation < anchor_generation {
            return Err(RoomStateVaultError::Rollback {
                record_generation: decoded.generation,
                anchor_generation,
            });
        }
        let state = RelayRoomState::restore(decoded.snapshot, now, limits)
            .map_err(RoomStateVaultError::Corrupt)?;
        if decoded.generation > anchor_generation {
            self.anchor
                .store_generation(&self.store_context, &self.relay_pubkey, decoded.generation)
                .map_err(RoomStateVaultError::Anchor)?;
        }
        self.generation = decoded.generation;
        Ok((
            state,
            RoomStateLoad::Restored {
                generation: decoded.generation,
            },
        ))
    }

    /// Persist a snapshot as the next generation. Either the previous valid
    /// state or the new one is on disk afterwards, never a mixture.
    pub fn persist(&mut self, state: &RelayRoomState) -> Result<u64, RoomStateVaultError> {
        if state.relay_pubkey() != self.relay_pubkey {
            return Err(RoomStateVaultError::RelayMismatch);
        }
        let anchored = self
            .anchor
            .load_generation(&self.store_context, &self.relay_pubkey)
            .map_err(RoomStateVaultError::Anchor)?;
        match anchored {
            None if self.generation == 0 => self
                .anchor
                .store_generation(&self.store_context, &self.relay_pubkey, 0)
                .map_err(RoomStateVaultError::Anchor)?,
            Some(generation) if generation == self.generation => {}
            None => return Err(RoomStateVaultError::MissingAnchor),
            Some(anchor_generation) => {
                return Err(RoomStateVaultError::Rollback {
                    record_generation: self.generation,
                    anchor_generation,
                });
            }
        }
        let generation = self
            .generation
            .checked_add(1)
            .ok_or(RoomStateVaultError::Encoding)?;
        let record = SealedRoomStateRecord {
            record_version: ROOM_STATE_RECORD_VERSION,
            store_context: self.store_context.clone(),
            relay_pubkey: self.relay_pubkey.clone(),
            generation,
            snapshot: state.snapshot(),
        };
        // Heap buffers only: the snapshot can approach the record ceiling.
        let encoded = serde_json::to_vec(&record).map_err(|_| RoomStateVaultError::Encoding)?;
        if encoded.len() > MAX_ROOM_STATE_PLAINTEXT_BYTES {
            return Err(RoomStateVaultError::RecordTooLarge);
        }
        self.store
            .write(&self.record_name, &encoded)
            .map_err(RoomStateVaultError::Store)?;
        self.anchor
            .store_generation(&self.store_context, &self.relay_pubkey, generation)
            .map_err(RoomStateVaultError::Anchor)?;
        self.generation = generation;
        Ok(generation)
    }
}

#[derive(Debug)]
pub enum RoomStateVaultError {
    Store(StoreError),
    Anchor(RoomStateAnchorError),
    Encoding,
    InvalidContext,
    InvalidRelayPublicKey,
    UnsupportedVersion(u16),
    ContextMismatch,
    RelayMismatch,
    MissingAnchor,
    Rollback {
        record_generation: u64,
        anchor_generation: u64,
    },
    RecordTooLarge,
    Corrupt(RoomStateError),
}

impl fmt::Display for RoomStateVaultError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Store(error) => write!(formatter, "room state storage failed: {error}"),
            Self::Anchor(error) => {
                write!(formatter, "room state generation anchor failed: {error}")
            }
            Self::Encoding => formatter.write_str("room state record encoding is invalid"),
            Self::InvalidContext => {
                formatter.write_str("room state store context must be 1 to 128 bytes")
            }
            Self::InvalidRelayPublicKey => {
                formatter.write_str("room state relay identity must be a lowercase 32-byte key")
            }
            Self::UnsupportedVersion(version) => {
                write!(formatter, "unsupported room state record version {version}")
            }
            Self::ContextMismatch => {
                formatter.write_str("room state record belongs to another store context")
            }
            Self::RelayMismatch => {
                formatter.write_str("room state record belongs to another relay identity")
            }
            Self::MissingAnchor => formatter
                .write_str("room state record exists without its external generation anchor"),
            Self::Rollback {
                record_generation,
                anchor_generation,
            } => write!(
                formatter,
                "room state generation {record_generation} is behind external anchor {anchor_generation}; refusing rolled-back state"
            ),
            Self::RecordTooLarge => {
                formatter.write_str("room state exceeds the sealed record ceiling")
            }
            Self::Corrupt(error) => write!(formatter, "room state failed validation: {error}"),
        }
    }
}

impl Error for RoomStateVaultError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Store(error) => Some(error),
            Self::Anchor(error) => Some(error),
            Self::Corrupt(error) => Some(error),
            _ => None,
        }
    }
}
