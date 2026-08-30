//! Canonical NIP-01 event identifiers and BIP-340 signatures.

use k256::schnorr::{Signature, SigningKey, VerifyingKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{error::Error, fmt};

pub type Tag = Vec<String>;

/// Derive the even-Y x-only public key used by Nostr from a secret key.
pub fn xonly_public_key(secret_key: &[u8; 32]) -> Result<[u8; 32], EventError> {
    let signing_key = SigningKey::from_bytes(secret_key).map_err(|_| EventError::SecretKey)?;
    Ok(signing_key.verifying_key().to_bytes().into())
}

/// Fields committed by a NIP-01 event identifier.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct UnsignedEvent {
    pub pubkey: String,
    pub created_at: u64,
    pub kind: u32,
    pub tags: Vec<Tag>,
    pub content: String,
}

impl UnsignedEvent {
    /// Construct an event and validate all fields covered by local limits.
    pub fn new(
        pubkey: String,
        created_at: u64,
        kind: u32,
        tags: Vec<Tag>,
        content: String,
        limits: &EventLimits,
    ) -> Result<Self, EventError> {
        let event = Self {
            pubkey,
            created_at,
            kind,
            tags,
            content,
        };
        event.validate(limits)?;
        Ok(event)
    }

    /// Return compact NIP-01 canonical JSON: `[0,pubkey,time,kind,tags,content]`.
    pub fn canonical_json(&self) -> Result<Vec<u8>, EventError> {
        serde_json::to_vec(&(
            0,
            &self.pubkey,
            self.created_at,
            self.kind,
            &self.tags,
            &self.content,
        ))
        .map_err(EventError::Json)
    }

    /// Compute the 32-byte NIP-01 event identifier.
    pub fn id(&self) -> Result<[u8; 32], EventError> {
        Ok(Sha256::digest(self.canonical_json()?).into())
    }

    /// Sign this event identifier using BIP-340 and explicit auxiliary bytes.
    ///
    /// Production callers must supply fresh CSPRNG output. Explicit input keeps
    /// conformance captures reproducible and avoids hidden ambient randomness.
    pub fn sign_with_aux(
        self,
        secret_key: &[u8; 32],
        auxiliary_randomness: &[u8; 32],
        limits: &EventLimits,
    ) -> Result<SignedEvent, EventError> {
        self.validate(limits)?;
        let signing_key = SigningKey::from_bytes(secret_key).map_err(|_| EventError::SecretKey)?;
        let verifying_bytes = signing_key.verifying_key().to_bytes();
        if verifying_bytes[..] != decode_hex_32(&self.pubkey)? {
            return Err(EventError::PublicKeyMismatch);
        }
        let id = self.id()?;
        let signature = signing_key
            .sign_raw(&id, auxiliary_randomness)
            .map_err(|_| EventError::Signing)?;

        Ok(SignedEvent {
            id: hex::encode(id),
            pubkey: self.pubkey,
            created_at: self.created_at,
            kind: self.kind,
            tags: self.tags,
            content: self.content,
            sig: hex::encode(signature.to_bytes()),
        })
    }

    fn validate(&self, limits: &EventLimits) -> Result<(), EventError> {
        decode_hex_32(&self.pubkey).map(|_| ())?;
        if self.content.len() > limits.max_content_bytes {
            return Err(EventError::ContentTooLarge {
                bytes: self.content.len(),
                maximum: limits.max_content_bytes,
            });
        }
        if self.tags.len() > limits.max_tags {
            return Err(EventError::TooManyTags {
                count: self.tags.len(),
                maximum: limits.max_tags,
            });
        }
        for (tag_index, tag) in self.tags.iter().enumerate() {
            if tag.len() > limits.max_tag_fields {
                return Err(EventError::TooManyTagFields {
                    tag_index,
                    count: tag.len(),
                    maximum: limits.max_tag_fields,
                });
            }
            for (field_index, field) in tag.iter().enumerate() {
                if field.len() > limits.max_tag_field_bytes {
                    return Err(EventError::TagFieldTooLarge {
                        tag_index,
                        field_index,
                        bytes: field.len(),
                        maximum: limits.max_tag_field_bytes,
                    });
                }
            }
        }
        Ok(())
    }
}

/// A strict signed NIP-01 event. Unknown and duplicate JSON fields are rejected
/// by Serde's derived struct decoder.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SignedEvent {
    pub id: String,
    pub pubkey: String,
    pub created_at: u64,
    pub kind: u32,
    pub tags: Vec<Tag>,
    pub content: String,
    pub sig: String,
}

impl SignedEvent {
    /// Decode and authenticate one JSON event under explicit resource/time limits.
    pub fn from_json(bytes: &[u8], now: u64, limits: &EventLimits) -> Result<Self, EventError> {
        if bytes.len() > limits.max_serialized_bytes {
            return Err(EventError::SerializedTooLarge {
                bytes: bytes.len(),
                maximum: limits.max_serialized_bytes,
            });
        }
        let event: Self = serde_json::from_slice(bytes).map_err(EventError::Json)?;
        event.verify(now, limits)?;
        Ok(event)
    }

    /// Verify field limits, time policy, event ID, public key, and signature.
    pub fn verify(&self, now: u64, limits: &EventLimits) -> Result<(), EventError> {
        let serialized_bytes = serde_json::to_vec(self).map_err(EventError::Json)?.len();
        if serialized_bytes > limits.max_serialized_bytes {
            return Err(EventError::SerializedTooLarge {
                bytes: serialized_bytes,
                maximum: limits.max_serialized_bytes,
            });
        }
        if self.created_at > now.saturating_add(limits.max_future_seconds) {
            return Err(EventError::TooFarInFuture {
                created_at: self.created_at,
                maximum: now.saturating_add(limits.max_future_seconds),
            });
        }

        let unsigned = self.unsigned();
        unsigned.validate(limits)?;
        let expected_id = unsigned.id()?;
        let supplied_id = decode_hex_32(&self.id)?;
        if expected_id != supplied_id {
            return Err(EventError::IdMismatch);
        }

        let public_key = decode_hex_32(&self.pubkey)?;
        let verifying_key =
            VerifyingKey::from_bytes(&public_key).map_err(|_| EventError::PublicKey)?;
        let signature_bytes = decode_hex_64(&self.sig)?;
        let signature =
            Signature::try_from(&signature_bytes[..]).map_err(|_| EventError::Signature)?;
        verifying_key
            .verify_raw(&expected_id, &signature)
            .map_err(|_| EventError::Signature)
    }

    /// Return the fields committed by this event's identifier.
    #[must_use]
    pub fn unsigned(&self) -> UnsignedEvent {
        UnsignedEvent {
            pubkey: self.pubkey.clone(),
            created_at: self.created_at,
            kind: self.kind,
            tags: self.tags.clone(),
            content: self.content.clone(),
        }
    }
}

/// Explicit local resource and timestamp policy for hostile relay input.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct EventLimits {
    pub max_serialized_bytes: usize,
    pub max_content_bytes: usize,
    pub max_tags: usize,
    pub max_tag_fields: usize,
    pub max_tag_field_bytes: usize,
    pub max_future_seconds: u64,
}

impl Default for EventLimits {
    fn default() -> Self {
        // Match the pinned Swift transport's hostile-input boundaries where
        // it defines them; keep the 15-minute window aligned with its outer
        // timestamp privacy range.
        Self {
            max_serialized_bytes: 256 * 1024,
            max_content_bytes: 64 * 1024,
            max_tags: 64,
            max_tag_fields: 16,
            max_tag_field_bytes: 1024,
            max_future_seconds: 15 * 60,
        }
    }
}

/// Fail-closed event decoding and authentication errors.
#[derive(Debug)]
pub enum EventError {
    Json(serde_json::Error),
    InvalidHex {
        expected_bytes: usize,
    },
    SecretKey,
    PublicKey,
    PublicKeyMismatch,
    Signing,
    Signature,
    IdMismatch,
    SerializedTooLarge {
        bytes: usize,
        maximum: usize,
    },
    ContentTooLarge {
        bytes: usize,
        maximum: usize,
    },
    TooManyTags {
        count: usize,
        maximum: usize,
    },
    TooManyTagFields {
        tag_index: usize,
        count: usize,
        maximum: usize,
    },
    TagFieldTooLarge {
        tag_index: usize,
        field_index: usize,
        bytes: usize,
        maximum: usize,
    },
    TooFarInFuture {
        created_at: u64,
        maximum: u64,
    },
}

impl fmt::Display for EventError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Json(error) => write!(formatter, "invalid event JSON: {error}"),
            Self::InvalidHex { expected_bytes } => write!(
                formatter,
                "event hex field must be lowercase and exactly {expected_bytes} bytes"
            ),
            Self::SecretKey => formatter.write_str("invalid secp256k1 secret key"),
            Self::PublicKey => formatter.write_str("invalid x-only secp256k1 public key"),
            Self::PublicKeyMismatch => {
                formatter.write_str("event public key does not match signing key")
            }
            Self::Signing => formatter.write_str("Schnorr signing failed"),
            Self::Signature => formatter.write_str("invalid Schnorr signature"),
            Self::IdMismatch => formatter.write_str("event identifier does not match its fields"),
            Self::SerializedTooLarge { bytes, maximum } => {
                write!(
                    formatter,
                    "event JSON is {bytes} bytes; maximum is {maximum}"
                )
            }
            Self::ContentTooLarge { bytes, maximum } => {
                write!(
                    formatter,
                    "event content is {bytes} bytes; maximum is {maximum}"
                )
            }
            Self::TooManyTags { count, maximum } => {
                write!(formatter, "event has {count} tags; maximum is {maximum}")
            }
            Self::TooManyTagFields {
                tag_index,
                count,
                maximum,
            } => write!(
                formatter,
                "event tag {tag_index} has {count} fields; maximum is {maximum}"
            ),
            Self::TagFieldTooLarge {
                tag_index,
                field_index,
                bytes,
                maximum,
            } => write!(
                formatter,
                "event tag {tag_index} field {field_index} is {bytes} bytes; maximum is {maximum}"
            ),
            Self::TooFarInFuture {
                created_at,
                maximum,
            } => write!(
                formatter,
                "event timestamp {created_at} exceeds accepted maximum {maximum}"
            ),
        }
    }
}

impl Error for EventError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Json(error) => Some(error),
            _ => None,
        }
    }
}

fn decode_hex_32(value: &str) -> Result<[u8; 32], EventError> {
    decode_hex(value)
}

fn decode_hex_64(value: &str) -> Result<[u8; 64], EventError> {
    decode_hex(value)
}

fn decode_hex<const N: usize>(value: &str) -> Result<[u8; N], EventError> {
    if value.len() != N * 2
        || value
            .bytes()
            .any(|byte| !byte.is_ascii_digit() && !(b'a'..=b'f').contains(&byte))
    {
        return Err(EventError::InvalidHex { expected_bytes: N });
    }
    let mut bytes = [0; N];
    hex::decode_to_slice(value, &mut bytes)
        .map_err(|_| EventError::InvalidHex { expected_bytes: N })?;
    Ok(bytes)
}
