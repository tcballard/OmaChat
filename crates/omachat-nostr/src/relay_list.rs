//! Standard NIP-65 relay-list publication.

use std::{collections::BTreeMap, error::Error, fmt};

use url::Url;

use crate::discovery::{NIP65_RELAY_LIST_KIND, RelayDiscoveryLimits, RelayPreference};
use crate::event::{EventLimits, SignedEvent, UnsignedEvent, xonly_public_key};

pub fn create_nip65_relay_list(
    secret_key: &[u8; 32],
    created_at: u64,
    relays: &[RelayPreference],
    event_limits: &EventLimits,
    discovery_limits: &RelayDiscoveryLimits,
) -> Result<SignedEvent, RelayListPublicationError> {
    let mut auxiliary_randomness = [0; 32];
    getrandom::fill(&mut auxiliary_randomness).map_err(|_| RelayListPublicationError::Random)?;
    create_nip65_relay_list_with_aux(
        secret_key,
        created_at,
        relays,
        &auxiliary_randomness,
        event_limits,
        discovery_limits,
    )
}

pub fn create_nip65_relay_list_with_aux(
    secret_key: &[u8; 32],
    created_at: u64,
    relays: &[RelayPreference],
    auxiliary_randomness: &[u8; 32],
    event_limits: &EventLimits,
    discovery_limits: &RelayDiscoveryLimits,
) -> Result<SignedEvent, RelayListPublicationError> {
    let relays = canonical_preferences(relays, discovery_limits)?;
    let public_key = xonly_public_key(secret_key)
        .map_err(|error| RelayListPublicationError::InvalidKey(error.to_string()))?;
    let tags = relays
        .into_iter()
        .map(|relay| {
            let mut tag = vec!["r".to_owned(), relay.url];
            match (relay.read, relay.write) {
                (true, false) => tag.push("read".to_owned()),
                (false, true) => tag.push("write".to_owned()),
                (true, true) => {}
                (false, false) => unreachable!("preferences are validated before signing"),
            }
            tag
        })
        .collect();
    let event = UnsignedEvent::new(
        hex::encode(public_key),
        created_at,
        NIP65_RELAY_LIST_KIND,
        tags,
        String::new(),
        event_limits,
    )
    .map_err(|error| RelayListPublicationError::InvalidEvent(error.to_string()))?;
    event
        .sign_with_aux(secret_key, auxiliary_randomness, event_limits)
        .map_err(|error| RelayListPublicationError::InvalidEvent(error.to_string()))
}

fn canonical_preferences(
    relays: &[RelayPreference],
    limits: &RelayDiscoveryLimits,
) -> Result<Vec<RelayPreference>, RelayListPublicationError> {
    if limits.max_relays == 0 || limits.max_url_bytes == 0 {
        return Err(RelayListPublicationError::InvalidLimits);
    }
    if relays.is_empty() {
        return Err(RelayListPublicationError::NoRelays);
    }
    if relays.len() > limits.max_relays {
        return Err(RelayListPublicationError::TooManyRelays {
            maximum: limits.max_relays,
        });
    }

    let mut merged = BTreeMap::<String, (bool, bool)>::new();
    for relay in relays {
        if !relay.read && !relay.write {
            return Err(RelayListPublicationError::InvalidPreference);
        }
        let endpoint = canonical_endpoint(&relay.url, limits.max_url_bytes)?;
        let entry = merged.entry(endpoint).or_default();
        entry.0 |= relay.read;
        entry.1 |= relay.write;
    }

    Ok(merged
        .into_iter()
        .map(|(url, (read, write))| RelayPreference { url, read, write })
        .collect())
}

fn canonical_endpoint(
    endpoint: &str,
    max_url_bytes: usize,
) -> Result<String, RelayListPublicationError> {
    if endpoint.is_empty() || endpoint.len() > max_url_bytes {
        return Err(RelayListPublicationError::InvalidEndpoint);
    }
    let parsed = Url::parse(endpoint).map_err(|_| RelayListPublicationError::InvalidEndpoint)?;
    let secure = parsed.scheme() == "wss";
    let numeric_loopback = parsed.scheme() == "ws"
        && match parsed.host() {
            Some(url::Host::Ipv4(address)) => address.is_loopback(),
            Some(url::Host::Ipv6(address)) => address.is_loopback(),
            _ => false,
        };
    if (!secure && !numeric_loopback)
        || parsed.host_str().is_none()
        || parsed.port_or_known_default().is_none()
        || !parsed.username().is_empty()
        || parsed.password().is_some()
        || parsed.query().is_some()
        || parsed.fragment().is_some()
    {
        return Err(RelayListPublicationError::InvalidEndpoint);
    }
    Ok(parsed.to_string())
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum RelayListPublicationError {
    Random,
    InvalidKey(String),
    InvalidEvent(String),
    InvalidLimits,
    InvalidPreference,
    InvalidEndpoint,
    NoRelays,
    TooManyRelays { maximum: usize },
}

impl fmt::Display for RelayListPublicationError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Random => formatter.write_str("secure randomness unavailable"),
            Self::InvalidKey(error) => write!(formatter, "invalid Nostr key: {error}"),
            Self::InvalidEvent(error) => write!(formatter, "invalid NIP-65 event: {error}"),
            Self::InvalidLimits => formatter.write_str("invalid relay-list limits"),
            Self::InvalidPreference => {
                formatter.write_str("relay preference must permit reads, writes, or both")
            }
            Self::InvalidEndpoint => {
                formatter.write_str("invalid or insecure NIP-65 relay endpoint")
            }
            Self::NoRelays => {
                formatter.write_str("NIP-65 relay list requires at least one endpoint")
            }
            Self::TooManyRelays { maximum } => {
                write!(formatter, "NIP-65 relay list exceeds maximum of {maximum}")
            }
        }
    }
}

impl Error for RelayListPublicationError {}
