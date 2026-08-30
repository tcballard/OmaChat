//! Bitchat-compatible private Nostr envelopes (kinds 14 → 13 → 1059).

use crate::event::{EventError, EventLimits, SignedEvent, Tag, UnsignedEvent, xonly_public_key};
use omachat_crypto::{CryptoError, open_from_xonly_peer, private_envelope_key, seal};
use serde::{Deserialize, Serialize};
use std::{error::Error, fmt};

pub const RUMOR_KIND: u32 = 14;
pub const SEAL_KIND: u32 = 13;
pub const GIFT_WRAP_KIND: u32 = 1059;

/// Released inner-event variants accepted by the pinned mobile clients.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RumorShape {
    SwiftTagless,
    SwiftRecipientTag,
    AndroidRecipientTag,
}

/// Deterministic inputs for a private-envelope creation operation.
///
/// Nonces and signing auxiliary bytes are explicit for conformance tests.
/// Production callers must fill them from a CSPRNG and choose privacy-rounded
/// outer timestamps according to the product policy.
pub struct CreateEnvelope<'a> {
    pub sender_secret_key: &'a [u8; 32],
    pub recipient_xonly_public_key: &'a [u8; 32],
    pub one_time_secret_key: &'a [u8; 32],
    pub content: &'a str,
    pub rumor_created_at: u64,
    pub seal_created_at: u64,
    pub gift_wrap_created_at: u64,
    pub seal_nonce: &'a [u8; 24],
    pub gift_wrap_nonce: &'a [u8; 24],
    pub seal_signature_aux: &'a [u8; 32],
    pub gift_wrap_signature_aux: &'a [u8; 32],
    pub rumor_shape: RumorShape,
}

/// Create a signed gift wrap compatible with the pinned Swift and Android
/// private-envelope shapes.
pub fn create(
    input: &CreateEnvelope<'_>,
    limits: &EventLimits,
) -> Result<SignedEvent, EnvelopeError> {
    let sender_pubkey = hex::encode(xonly_public_key(input.sender_secret_key)?);
    let recipient_pubkey = hex::encode(input.recipient_xonly_public_key);
    let one_time_pubkey = hex::encode(xonly_public_key(input.one_time_secret_key)?);
    let tags = match input.rumor_shape {
        RumorShape::SwiftTagless => vec![],
        RumorShape::SwiftRecipientTag | RumorShape::AndroidRecipientTag => {
            vec![recipient_tag(&recipient_pubkey)]
        }
    };
    let mut rumor = RumorEvent {
        content: input.content.to_owned(),
        created_at: input.rumor_created_at,
        id: String::new(),
        kind: RUMOR_KIND,
        pubkey: sender_pubkey.clone(),
        tags,
    };
    rumor.validate(&recipient_pubkey, limits)?;
    if input.rumor_shape == RumorShape::AndroidRecipientTag {
        rumor.id = hex::encode(rumor.unsigned(limits)?.id()?);
    }
    let rumor_json = serde_json::to_vec(&rumor).map_err(EnvelopeError::Json)?;

    let seal_key = private_envelope_key(input.sender_secret_key, input.recipient_xonly_public_key)?;
    let seal_content = seal(
        &seal_key,
        input.seal_nonce,
        &rumor_json,
        limits.max_serialized_bytes,
    )?;
    let seal_event = UnsignedEvent::new(
        sender_pubkey,
        input.seal_created_at,
        SEAL_KIND,
        vec![],
        seal_content,
        limits,
    )?
    .sign_with_aux(input.sender_secret_key, input.seal_signature_aux, limits)?;
    let seal_json =
        serde_json::to_vec(&SortedSignedEvent::from(&seal_event)).map_err(EnvelopeError::Json)?;

    let gift_key =
        private_envelope_key(input.one_time_secret_key, input.recipient_xonly_public_key)?;
    let gift_content = seal(
        &gift_key,
        input.gift_wrap_nonce,
        &seal_json,
        limits.max_serialized_bytes,
    )?;
    Ok(UnsignedEvent::new(
        one_time_pubkey,
        input.gift_wrap_created_at,
        GIFT_WRAP_KIND,
        vec![recipient_tag(&recipient_pubkey)],
        gift_content,
        limits,
    )?
    .sign_with_aux(
        input.one_time_secret_key,
        input.gift_wrap_signature_aux,
        limits,
    )?)
}

/// Authenticated private message returned after opening both envelope layers.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OpenedEnvelope {
    pub content: String,
    pub sender_pubkey: String,
    pub true_created_at: u64,
}

/// Authenticate and open a kind-1059 gift wrap and its kind-13 seal.
pub fn open_gift_wrap(
    gift_wrap: &SignedEvent,
    recipient_secret_key: &[u8; 32],
    now: u64,
    limits: &EventLimits,
) -> Result<OpenedEnvelope, EnvelopeError> {
    gift_wrap.verify(now, limits)?;
    if gift_wrap.kind != GIFT_WRAP_KIND {
        return Err(EnvelopeError::WrongKind {
            expected: GIFT_WRAP_KIND,
            actual: gift_wrap.kind,
        });
    }
    let recipient_pubkey = hex::encode(xonly_public_key(recipient_secret_key)?);
    if gift_wrap.tags != vec![recipient_tag(&recipient_pubkey)] {
        return Err(EnvelopeError::RecipientTag);
    }

    let seal_json = open_from_xonly_peer(
        recipient_secret_key,
        &decode_xonly(&gift_wrap.pubkey)?,
        &gift_wrap.content,
        limits.max_serialized_bytes,
    )?;
    let seal_event: SignedEvent =
        serde_json::from_slice(&seal_json).map_err(EnvelopeError::Json)?;
    seal_event.verify(now, limits)?;
    if seal_event.kind != SEAL_KIND {
        return Err(EnvelopeError::WrongKind {
            expected: SEAL_KIND,
            actual: seal_event.kind,
        });
    }
    if !seal_event.tags.is_empty() {
        return Err(EnvelopeError::SealTags);
    }

    let rumor_json = open_from_xonly_peer(
        recipient_secret_key,
        &decode_xonly(&seal_event.pubkey)?,
        &seal_event.content,
        limits.max_serialized_bytes,
    )?;
    let rumor: RumorEvent = serde_json::from_slice(&rumor_json).map_err(EnvelopeError::Json)?;
    rumor.validate(&recipient_pubkey, limits)?;
    if rumor.pubkey != seal_event.pubkey {
        return Err(EnvelopeError::SenderMismatch);
    }

    Ok(OpenedEnvelope {
        content: rumor.content,
        sender_pubkey: rumor.pubkey,
        true_created_at: rumor.created_at,
    })
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct RumorEvent {
    // Declaration order intentionally matches the captured sorted JSON bytes.
    content: String,
    created_at: u64,
    id: String,
    kind: u32,
    pubkey: String,
    tags: Vec<Tag>,
}

impl RumorEvent {
    fn unsigned(&self, limits: &EventLimits) -> Result<UnsignedEvent, EnvelopeError> {
        Ok(UnsignedEvent::new(
            self.pubkey.clone(),
            self.created_at,
            self.kind,
            self.tags.clone(),
            self.content.clone(),
            limits,
        )?)
    }

    fn validate(&self, recipient_pubkey: &str, limits: &EventLimits) -> Result<(), EnvelopeError> {
        if self.kind != RUMOR_KIND {
            return Err(EnvelopeError::WrongKind {
                expected: RUMOR_KIND,
                actual: self.kind,
            });
        }
        let unsigned = self.unsigned(limits)?;
        let accepted_tags =
            self.tags.is_empty() || self.tags == vec![recipient_tag(recipient_pubkey)];
        if !accepted_tags {
            return Err(EnvelopeError::RumorTags);
        }
        if !self.id.is_empty() && self.id != hex::encode(unsigned.id()?) {
            return Err(EnvelopeError::RumorId);
        }
        Ok(())
    }
}

#[derive(Serialize)]
struct SortedSignedEvent<'a> {
    content: &'a str,
    created_at: u64,
    id: &'a str,
    kind: u32,
    pubkey: &'a str,
    sig: &'a str,
    tags: &'a [Tag],
}

impl<'a> From<&'a SignedEvent> for SortedSignedEvent<'a> {
    fn from(event: &'a SignedEvent) -> Self {
        Self {
            content: &event.content,
            created_at: event.created_at,
            id: &event.id,
            kind: event.kind,
            pubkey: &event.pubkey,
            sig: &event.sig,
            tags: &event.tags,
        }
    }
}

#[derive(Debug)]
pub enum EnvelopeError {
    Event(EventError),
    Crypto(CryptoError),
    Json(serde_json::Error),
    InvalidPublicKey,
    WrongKind { expected: u32, actual: u32 },
    RecipientTag,
    SealTags,
    RumorTags,
    RumorId,
    SenderMismatch,
}

impl fmt::Display for EnvelopeError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Event(error) => write!(formatter, "invalid Nostr event: {error}"),
            Self::Crypto(error) => write!(formatter, "private-envelope crypto failed: {error}"),
            Self::Json(error) => write!(formatter, "invalid private-envelope JSON: {error}"),
            Self::InvalidPublicKey => formatter.write_str("invalid x-only public key"),
            Self::WrongKind { expected, actual } => {
                write!(formatter, "expected event kind {expected}, got {actual}")
            }
            Self::RecipientTag => formatter.write_str("invalid gift-wrap recipient tag"),
            Self::SealTags => formatter.write_str("kind-13 seal must not contain tags"),
            Self::RumorTags => formatter.write_str("unsupported kind-14 rumor tag shape"),
            Self::RumorId => formatter.write_str("kind-14 rumor ID does not match its fields"),
            Self::SenderMismatch => {
                formatter.write_str("kind-14 sender does not match signed kind-13 seal")
            }
        }
    }
}

impl Error for EnvelopeError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Event(error) => Some(error),
            Self::Crypto(error) => Some(error),
            Self::Json(error) => Some(error),
            _ => None,
        }
    }
}

impl From<EventError> for EnvelopeError {
    fn from(error: EventError) -> Self {
        Self::Event(error)
    }
}

impl From<CryptoError> for EnvelopeError {
    fn from(error: CryptoError) -> Self {
        Self::Crypto(error)
    }
}

fn recipient_tag(pubkey: &str) -> Tag {
    vec!["p".into(), pubkey.into()]
}

fn decode_xonly(value: &str) -> Result<[u8; 32], EnvelopeError> {
    let mut bytes = [0; 32];
    if value.len() != 64
        || value
            .bytes()
            .any(|byte| !byte.is_ascii_digit() && !(b'a'..=b'f').contains(&byte))
        || hex::decode_to_slice(value, &mut bytes).is_err()
    {
        return Err(EnvelopeError::InvalidPublicKey);
    }
    Ok(bytes)
}
