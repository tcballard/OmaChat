//! Authenticated peer pins, private payload framing, dedup, and route policy.

use crate::announce::{Announcement, AuthenticatedPeerState};
use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    collections::{HashMap, HashSet, VecDeque},
    error::Error,
    fmt,
};

pub const MAX_PRIVATE_TEXT_BYTES: usize = 4_096;
pub const PRIVATE_DEDUP_CAPACITY: usize = 1_000;
pub const MAX_TRUST_CONTROL_BYTES: usize = 2_048;

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "type", rename_all = "kebab-case", deny_unknown_fields)]
pub enum TrustControl {
    Favorite {
        fingerprint: String,
        nostr_public_key: String,
    },
    FavoriteAck {
        fingerprint: String,
        nostr_public_key: String,
    },
    Challenge {
        nonce: Vec<u8>,
    },
    ChallengeResponse {
        nonce: Vec<u8>,
        signature: Vec<u8>,
    },
    Vouch {
        fingerprint: String,
        noise_public_key: Vec<u8>,
        signing_public_key: Vec<u8>,
        signature: Vec<u8>,
    },
}

impl TrustControl {
    pub fn encode(&self) -> Result<Vec<u8>, PrivateError> {
        self.validate()?;
        let encoded = serde_json::to_vec(self).map_err(|_| PrivateError::TrustControl)?;
        if encoded.len() > MAX_TRUST_CONTROL_BYTES {
            return Err(PrivateError::TrustControl);
        }
        Ok(encoded)
    }
    pub fn decode(bytes: &[u8]) -> Result<Self, PrivateError> {
        if bytes.is_empty() || bytes.len() > MAX_TRUST_CONTROL_BYTES {
            return Err(PrivateError::TrustControl);
        }
        let value: Self = serde_json::from_slice(bytes).map_err(|_| PrivateError::TrustControl)?;
        value.validate()?;
        Ok(value)
    }
    fn validate(&self) -> Result<(), PrivateError> {
        let fingerprint = match self {
            Self::Favorite {
                fingerprint,
                nostr_public_key,
            }
            | Self::FavoriteAck {
                fingerprint,
                nostr_public_key,
            } => {
                validate_hex(nostr_public_key, 32)?;
                fingerprint
            }
            Self::Challenge { nonce } => {
                exact(nonce, 32)?;
                return Ok(());
            }
            Self::ChallengeResponse { nonce, signature } => {
                exact(nonce, 32)?;
                exact(signature, 64)?;
                return Ok(());
            }
            Self::Vouch {
                fingerprint,
                noise_public_key,
                signing_public_key,
                signature,
            } => {
                exact(noise_public_key, 32)?;
                exact(signing_public_key, 32)?;
                exact(signature, 64)?;
                fingerprint
            }
        };
        validate_hex(fingerprint, 32)
    }
}

pub fn verify_challenge(
    signing_public_key: &[u8; 32],
    nonce: &[u8],
    signature: &[u8],
) -> Result<(), PrivateError> {
    let signature: [u8; 64] = signature
        .try_into()
        .map_err(|_| PrivateError::TrustControl)?;
    VerifyingKey::from_bytes(signing_public_key)
        .map_err(|_| PrivateError::TrustControl)?
        .verify(nonce, &Signature::from_bytes(&signature))
        .map_err(|_| PrivateError::TrustControl)
}

fn exact(value: &[u8], length: usize) -> Result<(), PrivateError> {
    if value.len() == length {
        Ok(())
    } else {
        Err(PrivateError::TrustControl)
    }
}
fn validate_hex(value: &str, bytes: usize) -> Result<(), PrivateError> {
    if value.len() == bytes * 2 && hex::decode(value).is_ok() {
        Ok(())
    } else {
        Err(PrivateError::TrustControl)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct PeerPin {
    pub fingerprint: String,
    pub noise_public_key: [u8; 32],
    pub signing_public_key: [u8; 32],
    pub capabilities: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AnnouncementTrust {
    Untrusted,
    MatchesAuthenticatedPin,
}

#[derive(Default, Deserialize, Serialize)]
pub struct PeerPins {
    pins: HashMap<String, PeerPin>,
}

impl PeerPins {
    pub fn promote(&mut self, state: &AuthenticatedPeerState) -> Result<&PeerPin, PrivateError> {
        let fingerprint = hex::encode(Sha256::digest(state.noise_public_key));
        let proposed = PeerPin {
            fingerprint: fingerprint.clone(),
            noise_public_key: state.noise_public_key,
            signing_public_key: state.signing_public_key,
            capabilities: state.capabilities,
        };
        if let Some(existing) = self.pins.get(&fingerprint) {
            if existing.signing_public_key != proposed.signing_public_key
                || existing.noise_public_key != proposed.noise_public_key
            {
                return Err(PrivateError::PinMismatch);
            }
        } else {
            self.pins.insert(fingerprint.clone(), proposed);
        }
        Ok(self.pins.get(&fingerprint).expect("pin inserted"))
    }

    #[must_use]
    pub fn assess_announcement(&self, announcement: &Announcement) -> AnnouncementTrust {
        let fingerprint = hex::encode(Sha256::digest(announcement.noise_public_key));
        self.pins
            .get(&fingerprint)
            .filter(|pin| {
                pin.signing_public_key == announcement.signing_public_key
                    && pin.capabilities == announcement.capabilities
            })
            .map_or(AnnouncementTrust::Untrusted, |_| {
                AnnouncementTrust::MatchesAuthenticatedPin
            })
    }

    #[must_use]
    pub fn get(&self, fingerprint: &str) -> Option<&PeerPin> {
        self.pins.get(fingerprint)
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum PrivatePayload {
    Text {
        message_id: [u8; 16],
        timestamp_ms: u64,
        text: String,
    },
    Delivered {
        message_id: [u8; 16],
    },
    Read {
        message_id: [u8; 16],
    },
}

impl PrivatePayload {
    pub fn encode(&self) -> Result<Vec<u8>, PrivateError> {
        let mut output = Vec::new();
        match self {
            Self::Text {
                message_id,
                timestamp_ms,
                text,
            } => {
                if text.is_empty() || text.len() > MAX_PRIVATE_TEXT_BYTES {
                    return Err(PrivateError::Text);
                }
                output.push(1);
                output.extend_from_slice(message_id);
                output.extend_from_slice(&timestamp_ms.to_be_bytes());
                output.extend_from_slice(
                    &u16::try_from(text.len())
                        .map_err(|_| PrivateError::Text)?
                        .to_be_bytes(),
                );
                output.extend_from_slice(text.as_bytes());
            }
            Self::Delivered { message_id } => {
                output.push(2);
                output.extend_from_slice(message_id);
            }
            Self::Read { message_id } => {
                output.push(3);
                output.extend_from_slice(message_id);
            }
        }
        Ok(output)
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, PrivateError> {
        let kind = *bytes.first().ok_or(PrivateError::Truncated)?;
        match kind {
            1 => {
                if bytes.len() < 27 {
                    return Err(PrivateError::Truncated);
                }
                let length = usize::from(u16::from_be_bytes(
                    bytes[25..27].try_into().expect("fixed text length"),
                ));
                if length == 0 || length > MAX_PRIVATE_TEXT_BYTES || bytes.len() != 27 + length {
                    return Err(PrivateError::Text);
                }
                Ok(Self::Text {
                    message_id: bytes[1..17].try_into().expect("fixed message ID"),
                    timestamp_ms: u64::from_be_bytes(
                        bytes[17..25].try_into().expect("fixed timestamp"),
                    ),
                    text: String::from_utf8(bytes[27..].to_vec())
                        .map_err(|_| PrivateError::Text)?,
                })
            }
            2 | 3 if bytes.len() == 17 => {
                let message_id = bytes[1..].try_into().expect("fixed message ID");
                Ok(if kind == 2 {
                    Self::Delivered { message_id }
                } else {
                    Self::Read { message_id }
                })
            }
            2 | 3 => Err(PrivateError::Truncated),
            _ => Err(PrivateError::UnknownType),
        }
    }

    #[must_use]
    pub fn message_id(&self) -> [u8; 16] {
        match self {
            Self::Text { message_id, .. }
            | Self::Delivered { message_id }
            | Self::Read { message_id } => *message_id,
        }
    }
}

#[derive(Default)]
pub struct PrivateDedup {
    seen: HashSet<[u8; 16]>,
    order: VecDeque<[u8; 16]>,
}
impl PrivateDedup {
    pub fn insert(&mut self, id: [u8; 16]) -> bool {
        if !self.seen.insert(id) {
            return false;
        }
        self.order.push_back(id);
        if self.order.len() > PRIVATE_DEDUP_CAPACITY
            && let Some(old) = self.order.pop_front()
        {
            self.seen.remove(&old);
        }
        true
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PrivateRoute {
    Mesh,
    Nostr,
    Queue,
    RejectNotMutual,
}

#[must_use]
pub fn choose_private_route(
    mesh_reachable: bool,
    is_favorite: bool,
    mutually_favorited: bool,
    nostr_available: bool,
) -> PrivateRoute {
    if mesh_reachable {
        PrivateRoute::Mesh
    } else if is_favorite && mutually_favorited && nostr_available {
        PrivateRoute::Nostr
    } else if is_favorite && !mutually_favorited {
        PrivateRoute::RejectNotMutual
    } else {
        PrivateRoute::Queue
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PrivateError {
    PinMismatch,
    Text,
    Truncated,
    UnknownType,
    TrustControl,
}
impl fmt::Display for PrivateError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "private mesh error: {self:?}")
    }
}
impl Error for PrivateError {}
