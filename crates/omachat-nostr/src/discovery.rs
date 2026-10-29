//! Signature-verified NIP-65 and NIP-17 relay discovery.

use crate::event::{EventLimits, SignedEvent};
use std::{error::Error, fmt};
use url::Url;

pub const NIP65_RELAY_LIST_KIND: u32 = 10_002;
pub const NIP17_DM_RELAY_LIST_KIND: u32 = 10_050;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RelayDiscoveryLimits {
    pub max_relays: usize,
    pub max_url_bytes: usize,
}

impl Default for RelayDiscoveryLimits {
    fn default() -> Self {
        Self {
            max_relays: 16,
            max_url_bytes: 2_048,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RelayPreference {
    pub url: String,
    pub read: bool,
    pub write: bool,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RelayList {
    pub public_key: String,
    pub created_at: u64,
    pub relays: Vec<RelayPreference>,
}

pub fn parse_nip65_relay_list(
    event: &SignedEvent,
    now: u64,
    event_limits: &EventLimits,
    limits: &RelayDiscoveryLimits,
) -> Result<RelayList, RelayDiscoveryError> {
    event
        .verify(now, event_limits)
        .map_err(|error| RelayDiscoveryError::InvalidEvent(error.to_string()))?;
    if event.kind != NIP65_RELAY_LIST_KIND {
        return Err(RelayDiscoveryError::WrongKind {
            expected: NIP65_RELAY_LIST_KIND,
            actual: event.kind,
        });
    }
    validate_limits(limits)?;
    let mut relays = Vec::new();
    for tag in &event.tags {
        if tag.first().map(String::as_str) != Some("r") {
            continue;
        }
        let (read, write) = match tag.as_slice() {
            [_, _] => (true, true),
            [_, _, marker] if marker == "read" => (true, false),
            [_, _, marker] if marker == "write" => (false, true),
            _ => return Err(RelayDiscoveryError::InvalidRelayTag),
        };
        merge_relay(&mut relays, &tag[1], read, write, limits)?;
    }
    if relays.is_empty() {
        return Err(RelayDiscoveryError::EmptyRelayList);
    }
    Ok(RelayList {
        public_key: event.pubkey.clone(),
        created_at: event.created_at,
        relays,
    })
}

pub fn parse_nip17_dm_relay_list(
    event: &SignedEvent,
    now: u64,
    event_limits: &EventLimits,
    limits: &RelayDiscoveryLimits,
) -> Result<RelayList, RelayDiscoveryError> {
    event
        .verify(now, event_limits)
        .map_err(|error| RelayDiscoveryError::InvalidEvent(error.to_string()))?;
    if event.kind != NIP17_DM_RELAY_LIST_KIND {
        return Err(RelayDiscoveryError::WrongKind {
            expected: NIP17_DM_RELAY_LIST_KIND,
            actual: event.kind,
        });
    }
    validate_limits(limits)?;
    let mut relays = Vec::new();
    for tag in &event.tags {
        if tag.first().map(String::as_str) != Some("relay") {
            continue;
        }
        let [_, relay_url] = tag.as_slice() else {
            return Err(RelayDiscoveryError::InvalidRelayTag);
        };
        merge_relay(&mut relays, relay_url, true, true, limits)?;
    }
    if relays.is_empty() {
        return Err(RelayDiscoveryError::EmptyRelayList);
    }
    Ok(RelayList {
        public_key: event.pubkey.clone(),
        created_at: event.created_at,
        relays,
    })
}

fn validate_limits(limits: &RelayDiscoveryLimits) -> Result<(), RelayDiscoveryError> {
    if limits.max_relays == 0 || limits.max_url_bytes == 0 {
        Err(RelayDiscoveryError::InvalidLimits)
    } else {
        Ok(())
    }
}

fn merge_relay(
    relays: &mut Vec<RelayPreference>,
    raw_url: &str,
    read: bool,
    write: bool,
    limits: &RelayDiscoveryLimits,
) -> Result<(), RelayDiscoveryError> {
    let url = normalize_relay_url(raw_url, limits)?;
    if let Some(existing) = relays.iter_mut().find(|relay| relay.url == url) {
        existing.read |= read;
        existing.write |= write;
        return Ok(());
    }
    if relays.len() >= limits.max_relays {
        return Err(RelayDiscoveryError::TooManyRelays {
            maximum: limits.max_relays,
        });
    }
    relays.push(RelayPreference { url, read, write });
    Ok(())
}

fn normalize_relay_url(
    raw_url: &str,
    limits: &RelayDiscoveryLimits,
) -> Result<String, RelayDiscoveryError> {
    if raw_url.is_empty() || raw_url.len() > limits.max_url_bytes {
        return Err(RelayDiscoveryError::InvalidRelayUrl);
    }
    let parsed = Url::parse(raw_url).map_err(|_| RelayDiscoveryError::InvalidRelayUrl)?;
    if !matches!(parsed.scheme(), "ws" | "wss")
        || parsed.host_str().is_none()
        || parsed.port_or_known_default().is_none()
        || !parsed.username().is_empty()
        || parsed.password().is_some()
        || parsed.query().is_some()
        || parsed.fragment().is_some()
    {
        return Err(RelayDiscoveryError::InvalidRelayUrl);
    }
    Ok(parsed.to_string())
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum RelayDiscoveryError {
    InvalidEvent(String),
    WrongKind { expected: u32, actual: u32 },
    InvalidLimits,
    InvalidRelayTag,
    InvalidRelayUrl,
    EmptyRelayList,
    TooManyRelays { maximum: usize },
}

impl fmt::Display for RelayDiscoveryError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidEvent(error) => write!(formatter, "invalid relay-list event: {error}"),
            Self::WrongKind { expected, actual } => {
                write!(
                    formatter,
                    "expected relay-list kind {expected}, got {actual}"
                )
            }
            Self::InvalidLimits => formatter.write_str("invalid relay-discovery limits"),
            Self::InvalidRelayTag => formatter.write_str("invalid relay-list tag"),
            Self::InvalidRelayUrl => formatter.write_str("invalid relay URL"),
            Self::EmptyRelayList => formatter.write_str("relay-list event has no relays"),
            Self::TooManyRelays { maximum } => {
                write!(formatter, "relay list exceeds maximum of {maximum}")
            }
        }
    }
}

impl Error for RelayDiscoveryError {}
