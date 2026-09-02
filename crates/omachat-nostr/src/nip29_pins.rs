//! Ordered NIP-29 room pin snapshots and update requests.

use crate::event::{EventError, EventLimits, SignedEvent, Tag};
use std::{error::Error, fmt};

pub const UPDATE_PIN_LIST_KIND: u32 = 9010;
pub const GROUP_PIN_LIST_KIND: u32 = 39005;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GroupPinList {
    event: SignedEvent,
    group_id: String,
    pins: Vec<PinReference>,
}

impl GroupPinList {
    pub fn verify(
        event: SignedEvent,
        expected_relay_pubkey: &str,
        now: u64,
        limits: &EventLimits,
    ) -> Result<Self, GroupPinsError> {
        event.verify(now, limits).map_err(GroupPinsError::Event)?;
        if event.kind != GROUP_PIN_LIST_KIND {
            return Err(GroupPinsError::UnsupportedKind(event.kind));
        }
        if event.pubkey != expected_relay_pubkey {
            return Err(GroupPinsError::RelayAuthorMismatch);
        }
        let group_id = unique_pair_tag(&event.tags, "d")?.ok_or(GroupPinsError::MissingGroupId)?;
        if group_id.is_empty() {
            return Err(GroupPinsError::EmptyGroupId);
        }
        Ok(Self {
            pins: pin_references(&event.tags)?,
            event,
            group_id,
        })
    }

    #[must_use]
    pub fn event(&self) -> &SignedEvent {
        &self.event
    }

    #[must_use]
    pub fn group_id(&self) -> &str {
        &self.group_id
    }

    #[must_use]
    pub fn pins(&self) -> &[PinReference] {
        &self.pins
    }
}

/// A signed pin update request whose relay authorization is not implied.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GroupPinUpdate {
    event: SignedEvent,
    group_id: String,
    pins: Vec<PinReference>,
}

impl GroupPinUpdate {
    pub fn verify(
        event: SignedEvent,
        now: u64,
        limits: &EventLimits,
    ) -> Result<Self, GroupPinsError> {
        event.verify(now, limits).map_err(GroupPinsError::Event)?;
        if event.kind != UPDATE_PIN_LIST_KIND {
            return Err(GroupPinsError::UnsupportedKind(event.kind));
        }
        let group_id = unique_pair_tag(&event.tags, "h")?.ok_or(GroupPinsError::MissingGroupId)?;
        if group_id.is_empty() {
            return Err(GroupPinsError::EmptyGroupId);
        }
        Ok(Self {
            pins: pin_references(&event.tags)?,
            event,
            group_id,
        })
    }

    #[must_use]
    pub fn event(&self) -> &SignedEvent {
        &self.event
    }

    #[must_use]
    pub fn author(&self) -> &str {
        &self.event.pubkey
    }

    #[must_use]
    pub fn group_id(&self) -> &str {
        &self.group_id
    }

    #[must_use]
    pub fn pins(&self) -> &[PinReference] {
        &self.pins
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum PinReference {
    Event(String),
    Address(String),
}

fn pin_references(tags: &[Tag]) -> Result<Vec<PinReference>, GroupPinsError> {
    let mut pins = Vec::new();
    for tag in tags
        .iter()
        .filter(|tag| tag.first().is_some_and(|part| part == "e" || part == "a"))
    {
        if tag.len() != 2 {
            return Err(GroupPinsError::MalformedPinTag);
        }
        let pin = if tag[0] == "e" {
            validate_hex_id(&tag[1])?;
            PinReference::Event(tag[1].clone())
        } else {
            validate_address(&tag[1])?;
            PinReference::Address(tag[1].clone())
        };
        if pins.contains(&pin) {
            return Err(GroupPinsError::DuplicatePin);
        }
        pins.push(pin);
    }
    Ok(pins)
}

fn unique_pair_tag(tags: &[Tag], name: &'static str) -> Result<Option<String>, GroupPinsError> {
    let mut value = None;
    for tag in tags
        .iter()
        .filter(|tag| tag.first().is_some_and(|part| part == name))
    {
        if value.is_some() {
            return Err(GroupPinsError::DuplicateTag(name));
        }
        if tag.len() != 2 {
            return Err(GroupPinsError::MalformedTag(name));
        }
        value = Some(tag[1].clone());
    }
    Ok(value)
}

fn validate_hex_id(value: &str) -> Result<(), GroupPinsError> {
    if value.len() != 64
        || value
            .bytes()
            .any(|byte| !byte.is_ascii_digit() && !(b'a'..=b'f').contains(&byte))
    {
        return Err(GroupPinsError::InvalidEventId);
    }
    Ok(())
}

fn validate_address(value: &str) -> Result<(), GroupPinsError> {
    let mut fields = value.splitn(3, ':');
    let kind = fields
        .next()
        .and_then(|field| field.parse::<u32>().ok())
        .ok_or(GroupPinsError::InvalidAddress)?;
    let pubkey = fields.next().ok_or(GroupPinsError::InvalidAddress)?;
    let _identifier = fields.next().ok_or(GroupPinsError::InvalidAddress)?;
    if !(30_000..40_000).contains(&kind) {
        return Err(GroupPinsError::InvalidAddress);
    }
    validate_hex_id(pubkey).map_err(|_| GroupPinsError::InvalidAddress)
}

#[derive(Debug)]
pub enum GroupPinsError {
    Event(EventError),
    UnsupportedKind(u32),
    RelayAuthorMismatch,
    MissingGroupId,
    EmptyGroupId,
    DuplicateTag(&'static str),
    MalformedTag(&'static str),
    MalformedPinTag,
    InvalidEventId,
    InvalidAddress,
    DuplicatePin,
}

impl fmt::Display for GroupPinsError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Event(error) => write!(formatter, "invalid NIP-29 pin event: {error}"),
            Self::UnsupportedKind(kind) => write!(formatter, "unsupported NIP-29 pin kind {kind}"),
            Self::RelayAuthorMismatch => {
                formatter.write_str("NIP-29 pin-list author does not match the expected relay")
            }
            Self::MissingGroupId => formatter.write_str("NIP-29 pin event is missing group scope"),
            Self::EmptyGroupId => formatter.write_str("NIP-29 group ID must not be empty"),
            Self::DuplicateTag(name) => write!(formatter, "duplicate NIP-29 {name} tag"),
            Self::MalformedTag(name) => write!(formatter, "malformed NIP-29 {name} tag"),
            Self::MalformedPinTag => {
                formatter.write_str("NIP-29 pin tag must contain exactly one reference")
            }
            Self::InvalidEventId => {
                formatter.write_str("NIP-29 event pin must be a lowercase 32-byte event ID")
            }
            Self::InvalidAddress => {
                formatter.write_str("NIP-29 address pin must be a valid addressable coordinate")
            }
            Self::DuplicatePin => formatter.write_str("duplicate NIP-29 pin reference"),
        }
    }
}

impl Error for GroupPinsError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Event(error) => Some(error),
            _ => None,
        }
    }
}
