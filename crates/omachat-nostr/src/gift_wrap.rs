//! Standards-compatible NIP-59 gift wrapping and NIP-17 chat rumors.
//!
//! This is deliberately separate from OmaChat's captured mobile envelope.

use crate::event::{EventError, EventLimits, SignedEvent, Tag, UnsignedEvent, xonly_public_key};
use omachat_crypto::{Nip44Error, nip44_decrypt, nip44_encrypt_with_nonce};
use serde::{Deserialize, Serialize};
use std::{collections::BTreeSet, error::Error, fmt};
use url::Url;
use zeroize::Zeroizing;

pub const SEAL_KIND: u32 = 13;
pub const CHAT_MESSAGE_KIND: u32 = 14;
pub const GIFT_WRAP_KIND: u32 = 1059;
pub const EPHEMERAL_GIFT_WRAP_KIND: u32 = 21059;
pub const MAX_CHAT_RECIPIENTS: usize = 10;
const MAX_TIMESTAMP_SKEW_SECONDS: u64 = 2 * 24 * 60 * 60;

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Rumor {
    pub id: String,
    pub pubkey: String,
    pub created_at: u64,
    pub kind: u32,
    pub tags: Vec<Tag>,
    pub content: String,
}

impl Rumor {
    pub fn new(event: UnsignedEvent, limits: &EventLimits) -> Result<Self, GiftWrapError> {
        let event = UnsignedEvent::new(
            event.pubkey,
            event.created_at,
            event.kind,
            event.tags,
            event.content,
            limits,
        )?;
        Ok(Self {
            id: hex::encode(event.id()?),
            pubkey: event.pubkey,
            created_at: event.created_at,
            kind: event.kind,
            tags: event.tags,
            content: event.content,
        })
    }

    pub fn verify(&self, limits: &EventLimits) -> Result<(), GiftWrapError> {
        let event = UnsignedEvent::new(
            self.pubkey.clone(),
            self.created_at,
            self.kind,
            self.tags.clone(),
            self.content.clone(),
            limits,
        )?;
        if hex::encode(event.id()?) != self.id {
            return Err(GiftWrapError::RumorIdMismatch);
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ChatRecipient {
    pub public_key: [u8; 32],
    pub relay_hint: Option<String>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum GiftWrapPersistence {
    Persistent,
    Ephemeral,
}

impl GiftWrapPersistence {
    const fn kind(self) -> u32 {
        match self {
            Self::Persistent => GIFT_WRAP_KIND,
            Self::Ephemeral => EPHEMERAL_GIFT_WRAP_KIND,
        }
    }
}

pub struct GiftWrapMaterial {
    pub seal_created_at: u64,
    pub seal_nonce: [u8; 32],
    pub seal_auxiliary_randomness: [u8; 32],
    pub wrapper_secret_key: [u8; 32],
    pub wrapper_created_at: u64,
    pub wrapper_nonce: [u8; 32],
    pub wrapper_auxiliary_randomness: [u8; 32],
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OpenedGiftWrap {
    pub seal: SignedEvent,
    pub rumor: Rumor,
}

pub fn create_chat_rumor(
    sender_secret_key: &[u8; 32],
    created_at: u64,
    recipients: &[ChatRecipient],
    content: String,
    subject: Option<String>,
    reply_to: Option<String>,
    limits: &EventLimits,
) -> Result<Rumor, GiftWrapError> {
    if recipients.is_empty() || recipients.len() > MAX_CHAT_RECIPIENTS {
        return Err(GiftWrapError::InvalidRecipientCount);
    }
    let sender = hex::encode(xonly_public_key(sender_secret_key)?);
    let mut seen = BTreeSet::new();
    let mut tags = Vec::with_capacity(recipients.len() + 2);
    for recipient in recipients {
        let public_key = hex::encode(recipient.public_key);
        if public_key == sender || !seen.insert(public_key.clone()) {
            return Err(GiftWrapError::DuplicateOrSelfRecipient);
        }
        let mut tag = vec!["p".to_owned(), public_key];
        if let Some(relay) = &recipient.relay_hint {
            validate_relay_hint(relay)?;
            tag.push(relay.clone());
        }
        tags.push(tag);
    }
    if let Some(reply) = reply_to {
        validate_lower_hex(&reply, 32)?;
        tags.push(vec!["e".to_owned(), reply]);
    }
    if let Some(subject) = subject {
        tags.push(vec!["subject".to_owned(), subject]);
    }
    Rumor::new(
        UnsignedEvent::new(sender, created_at, CHAT_MESSAGE_KIND, tags, content, limits)?,
        limits,
    )
}

pub fn create_gift_wrap(
    rumor: &Rumor,
    sender_secret_key: &[u8; 32],
    recipient_public_key: &[u8; 32],
    now: u64,
    persistence: GiftWrapPersistence,
    limits: &EventLimits,
) -> Result<SignedEvent, GiftWrapError> {
    let material = GiftWrapMaterial {
        seal_created_at: random_past_timestamp(now)?,
        seal_nonce: random_array()?,
        seal_auxiliary_randomness: random_array()?,
        wrapper_secret_key: random_secret_key()?,
        wrapper_created_at: random_past_timestamp(now)?,
        wrapper_nonce: random_array()?,
        wrapper_auxiliary_randomness: random_array()?,
    };
    create_gift_wrap_with_material(
        rumor,
        sender_secret_key,
        recipient_public_key,
        persistence,
        material,
        limits,
    )
}

pub fn create_gift_wrap_with_material(
    rumor: &Rumor,
    sender_secret_key: &[u8; 32],
    recipient_public_key: &[u8; 32],
    persistence: GiftWrapPersistence,
    material: GiftWrapMaterial,
    limits: &EventLimits,
) -> Result<SignedEvent, GiftWrapError> {
    rumor.verify(limits)?;
    if rumor.pubkey != hex::encode(xonly_public_key(sender_secret_key)?) {
        return Err(GiftWrapError::AuthorMismatch);
    }
    let rumor_json = serde_json::to_string(rumor).map_err(GiftWrapError::Json)?;
    let encrypted_rumor = nip44_encrypt_with_nonce(
        sender_secret_key,
        recipient_public_key,
        &rumor_json,
        material.seal_nonce,
    )?;
    let seal = UnsignedEvent::new(
        rumor.pubkey.clone(),
        material.seal_created_at,
        SEAL_KIND,
        Vec::new(),
        encrypted_rumor,
        limits,
    )?
    .sign_with_aux(
        sender_secret_key,
        &material.seal_auxiliary_randomness,
        limits,
    )?;

    let wrapper_secret = Zeroizing::new(material.wrapper_secret_key);
    let wrapper_public = xonly_public_key(&wrapper_secret)?;
    let seal_json = serde_json::to_string(&seal).map_err(GiftWrapError::Json)?;
    let encrypted_seal = nip44_encrypt_with_nonce(
        &wrapper_secret,
        recipient_public_key,
        &seal_json,
        material.wrapper_nonce,
    )?;
    Ok(UnsignedEvent::new(
        hex::encode(wrapper_public),
        material.wrapper_created_at,
        persistence.kind(),
        vec![vec!["p".to_owned(), hex::encode(recipient_public_key)]],
        encrypted_seal,
        limits,
    )?
    .sign_with_aux(
        &wrapper_secret,
        &material.wrapper_auxiliary_randomness,
        limits,
    )?)
}

pub fn open_gift_wrap(
    gift_wrap: &SignedEvent,
    recipient_secret_key: &[u8; 32],
    now: u64,
    limits: &EventLimits,
) -> Result<OpenedGiftWrap, GiftWrapError> {
    gift_wrap.verify(now, limits)?;
    if !matches!(gift_wrap.kind, GIFT_WRAP_KIND | EPHEMERAL_GIFT_WRAP_KIND) {
        return Err(GiftWrapError::WrongWrapperKind);
    }
    let recipient = hex::encode(xonly_public_key(recipient_secret_key)?);
    let recipient_tags: Vec<&Tag> = gift_wrap
        .tags
        .iter()
        .filter(|tag| tag.first().is_some_and(|field| field == "p"))
        .collect();
    if recipient_tags.len() != 1
        || recipient_tags[0].get(1).map(String::as_str) != Some(recipient.as_str())
    {
        return Err(GiftWrapError::RecipientMismatch);
    }

    let wrapper_public = decode_lower_hex_32(&gift_wrap.pubkey)?;
    let seal_json = nip44_decrypt(recipient_secret_key, &wrapper_public, &gift_wrap.content)?;
    let seal = SignedEvent::from_json(seal_json.as_bytes(), now, limits)?;
    if seal.kind != SEAL_KIND {
        return Err(GiftWrapError::WrongSealKind);
    }
    if !seal.tags.is_empty() {
        return Err(GiftWrapError::SealHasTags);
    }
    let author_public = decode_lower_hex_32(&seal.pubkey)?;
    let rumor_json = nip44_decrypt(recipient_secret_key, &author_public, &seal.content)?;
    if rumor_json.len() > limits.max_serialized_bytes {
        return Err(GiftWrapError::RumorTooLarge);
    }
    let rumor: Rumor = serde_json::from_str(&rumor_json).map_err(GiftWrapError::Json)?;
    rumor.verify(limits)?;
    if rumor.pubkey != seal.pubkey {
        return Err(GiftWrapError::AuthorMismatch);
    }
    Ok(OpenedGiftWrap { seal, rumor })
}

fn validate_relay_hint(relay: &str) -> Result<(), GiftWrapError> {
    let parsed = Url::parse(relay).map_err(|_| GiftWrapError::InvalidRelayHint)?;
    if !matches!(parsed.scheme(), "ws" | "wss")
        || parsed.host_str().is_none()
        || !parsed.username().is_empty()
        || parsed.password().is_some()
        || parsed.fragment().is_some()
    {
        return Err(GiftWrapError::InvalidRelayHint);
    }
    Ok(())
}

fn validate_lower_hex(value: &str, bytes: usize) -> Result<(), GiftWrapError> {
    if value.len() != bytes * 2
        || value
            .bytes()
            .any(|byte| !byte.is_ascii_digit() && !(b'a'..=b'f').contains(&byte))
    {
        return Err(GiftWrapError::InvalidHex);
    }
    Ok(())
}

fn decode_lower_hex_32(value: &str) -> Result<[u8; 32], GiftWrapError> {
    validate_lower_hex(value, 32)?;
    hex::decode(value)
        .map_err(|_| GiftWrapError::InvalidHex)?
        .try_into()
        .map_err(|_| GiftWrapError::InvalidHex)
}

fn random_array() -> Result<[u8; 32], GiftWrapError> {
    let mut bytes = [0_u8; 32];
    getrandom::fill(&mut bytes).map_err(|_| GiftWrapError::RandomnessUnavailable)?;
    Ok(bytes)
}

fn random_secret_key() -> Result<[u8; 32], GiftWrapError> {
    for _ in 0..128 {
        let candidate = random_array()?;
        if k256::schnorr::SigningKey::from_bytes(&candidate).is_ok() {
            return Ok(candidate);
        }
    }
    Err(GiftWrapError::RandomnessUnavailable)
}

fn random_past_timestamp(now: u64) -> Result<u64, GiftWrapError> {
    let mut bytes = [0_u8; 8];
    getrandom::fill(&mut bytes).map_err(|_| GiftWrapError::RandomnessUnavailable)?;
    let offset = u64::from_le_bytes(bytes) % (MAX_TIMESTAMP_SKEW_SECONDS + 1);
    Ok(now.saturating_sub(offset))
}

#[derive(Debug)]
pub enum GiftWrapError {
    Event(EventError),
    Encryption(Nip44Error),
    Json(serde_json::Error),
    InvalidRecipientCount,
    DuplicateOrSelfRecipient,
    InvalidRelayHint,
    InvalidHex,
    RumorIdMismatch,
    AuthorMismatch,
    WrongWrapperKind,
    RecipientMismatch,
    WrongSealKind,
    SealHasTags,
    RumorTooLarge,
    RandomnessUnavailable,
}

impl From<EventError> for GiftWrapError {
    fn from(error: EventError) -> Self {
        Self::Event(error)
    }
}

impl From<Nip44Error> for GiftWrapError {
    fn from(error: Nip44Error) -> Self {
        Self::Encryption(error)
    }
}

impl fmt::Display for GiftWrapError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Event(error) => write!(formatter, "invalid Nostr event: {error}"),
            Self::Encryption(error) => write!(formatter, "NIP-44 failure: {error}"),
            Self::Json(error) => write!(formatter, "invalid gift-wrap JSON: {error}"),
            Self::InvalidRecipientCount => {
                formatter.write_str("chat recipient count must be 1 through 10")
            }
            Self::DuplicateOrSelfRecipient => {
                formatter.write_str("chat recipients must be unique and exclude the sender")
            }
            Self::InvalidRelayHint => {
                formatter.write_str("relay hint must be a valid ws or wss URL")
            }
            Self::InvalidHex => formatter.write_str("expected canonical lowercase hex"),
            Self::RumorIdMismatch => {
                formatter.write_str("rumor identifier does not match its fields")
            }
            Self::AuthorMismatch => {
                formatter.write_str("seal signer and rumor author do not match")
            }
            Self::WrongWrapperKind => formatter.write_str("event is not a NIP-59 gift wrap"),
            Self::RecipientMismatch => {
                formatter.write_str("gift wrap is not addressed exactly once to this recipient")
            }
            Self::WrongSealKind => formatter.write_str("gift-wrap content is not a kind 13 seal"),
            Self::SealHasTags => formatter.write_str("a kind 13 seal must not have tags"),
            Self::RumorTooLarge => {
                formatter.write_str("decrypted rumor exceeds the event resource limit")
            }
            Self::RandomnessUnavailable => formatter.write_str("secure randomness is unavailable"),
        }
    }
}

impl Error for GiftWrapError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Event(error) => Some(error),
            Self::Encryption(error) => Some(error),
            Self::Json(error) => Some(error),
            _ => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const OFFICIAL_EXAMPLE: &str =
        include_str!("../../../conformance/fixtures/nip59-example-gift-wrap.json");

    fn material(secret: [u8; 32]) -> GiftWrapMaterial {
        GiftWrapMaterial {
            seal_created_at: 1_700_000_001,
            seal_nonce: [4; 32],
            seal_auxiliary_randomness: [5; 32],
            wrapper_secret_key: secret,
            wrapper_created_at: 1_700_000_002,
            wrapper_nonce: [6; 32],
            wrapper_auxiliary_randomness: [7; 32],
        }
    }

    fn chat(sender: &[u8; 32], recipient: [u8; 32], limits: &EventLimits) -> Rumor {
        create_chat_rumor(
            sender,
            1_700_000_000,
            &[ChatRecipient {
                public_key: recipient,
                relay_hint: Some("wss://relay.example".to_owned()),
            }],
            "hello from the agent".to_owned(),
            Some("interop".to_owned()),
            None,
            limits,
        )
        .unwrap()
    }

    #[test]
    fn opens_the_official_nip59_example() {
        let recipient =
            hex::decode("e108399bd8424357a710b606ae0c13166d853d327e47a6e5e038197346bdbf45")
                .unwrap()
                .try_into()
                .unwrap();
        let gift_wrap: SignedEvent = serde_json::from_str(OFFICIAL_EXAMPLE).unwrap();
        let opened = open_gift_wrap(
            &gift_wrap,
            &recipient,
            1_703_100_000,
            &EventLimits::default(),
        )
        .unwrap();
        assert_eq!(opened.seal.kind, SEAL_KIND);
        assert!(opened.seal.tags.is_empty());
        assert_eq!(opened.rumor.content, "Are you going to the party tonight?");
        assert_eq!(opened.rumor.pubkey, opened.seal.pubkey);
    }

    #[test]
    fn round_trips_kind14_without_changing_authorship() {
        let sender = [1_u8; 32];
        let recipient_secret = [2_u8; 32];
        let recipient = xonly_public_key(&recipient_secret).unwrap();
        let limits = EventLimits::default();
        let rumor = chat(&sender, recipient, &limits);
        let wrap = create_gift_wrap_with_material(
            &rumor,
            &sender,
            &recipient,
            GiftWrapPersistence::Persistent,
            material([3; 32]),
            &limits,
        )
        .unwrap();
        assert_ne!(wrap.pubkey, rumor.pubkey);
        let opened = open_gift_wrap(&wrap, &recipient_secret, 1_700_000_010, &limits).unwrap();
        assert_eq!(opened.rumor, rumor);
        assert_eq!(opened.seal.pubkey, rumor.pubkey);
        assert_eq!(opened.rumor.kind, CHAT_MESSAGE_KIND);
    }

    #[test]
    fn rejects_forged_authorship_and_wrong_recipient() {
        let sender = [1_u8; 32];
        let recipient_secret = [2_u8; 32];
        let recipient = xonly_public_key(&recipient_secret).unwrap();
        let limits = EventLimits::default();
        let rumor = chat(&sender, recipient, &limits);
        assert!(matches!(
            create_gift_wrap_with_material(
                &rumor,
                &[9; 32],
                &recipient,
                GiftWrapPersistence::Persistent,
                material([3; 32]),
                &limits
            ),
            Err(GiftWrapError::AuthorMismatch)
        ));
        let wrap = create_gift_wrap_with_material(
            &rumor,
            &sender,
            &recipient,
            GiftWrapPersistence::Persistent,
            material([3; 32]),
            &limits,
        )
        .unwrap();
        assert!(matches!(
            open_gift_wrap(&wrap, &[8; 32], 1_700_000_010, &limits),
            Err(GiftWrapError::RecipientMismatch)
        ));
    }

    #[test]
    fn distinct_wraps_preserve_one_rumor_identity() {
        let sender = [1_u8; 32];
        let first_secret = [2_u8; 32];
        let second_secret = [8_u8; 32];
        let first = xonly_public_key(&first_secret).unwrap();
        let second = xonly_public_key(&second_secret).unwrap();
        let limits = EventLimits::default();
        let rumor = create_chat_rumor(
            &sender,
            1_700_000_000,
            &[
                ChatRecipient {
                    public_key: first,
                    relay_hint: None,
                },
                ChatRecipient {
                    public_key: second,
                    relay_hint: None,
                },
            ],
            "same identity".to_owned(),
            None,
            None,
            &limits,
        )
        .unwrap();
        let first_wrap = create_gift_wrap_with_material(
            &rumor,
            &sender,
            &first,
            GiftWrapPersistence::Persistent,
            material([3; 32]),
            &limits,
        )
        .unwrap();
        let second_wrap = create_gift_wrap_with_material(
            &rumor,
            &sender,
            &second,
            GiftWrapPersistence::Persistent,
            material([4; 32]),
            &limits,
        )
        .unwrap();
        let first_opened =
            open_gift_wrap(&first_wrap, &first_secret, 1_700_000_010, &limits).unwrap();
        let second_opened =
            open_gift_wrap(&second_wrap, &second_secret, 1_700_000_010, &limits).unwrap();
        assert_ne!(first_wrap.id, second_wrap.id);
        assert_eq!(first_opened.rumor.id, second_opened.rumor.id);
        assert_eq!(first_opened.rumor.pubkey, second_opened.rumor.pubkey);
    }
}
