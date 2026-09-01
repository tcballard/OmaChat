use std::{error::Error, fmt, time::Duration};

use crate::{
    auth::RelayAuthSigner,
    discovery::{
        NIP65_RELAY_LIST_KIND, RelayDiscoveryError, RelayDiscoveryLimits, RelayList,
        parse_nip65_relay_list,
    },
    event::{EventLimits, SignedEvent},
    relay::RelayConfig,
    replaceable_discovery::{ReplaceableDiscoveryConfig, discover_replaceable_event},
};

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RelayListDiscoveryConfig {
    pub authentication_timeout: Duration,
    pub query_timeout: Duration,
    pub minimum_authenticated_relays: usize,
    pub subscription_id: String,
}

impl Default for RelayListDiscoveryConfig {
    fn default() -> Self {
        Self {
            authentication_timeout: Duration::from_secs(10),
            query_timeout: Duration::from_secs(10),
            minimum_authenticated_relays: 1,
            subscription_id: "omachat-nip65-discovery".into(),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RelayListDiscoveryResult {
    pub event: SignedEvent,
    pub relay_list: RelayList,
    pub queried_relays: usize,
    pub completed_relays: usize,
}

pub async fn discover_nip65_relay_list(
    relay_configs: Vec<RelayConfig>,
    auth_signer: RelayAuthSigner,
    participant_public_key: &[u8; 32],
    now: u64,
    event_limits: &EventLimits,
    relay_limits: &RelayDiscoveryLimits,
    config: &RelayListDiscoveryConfig,
) -> Result<RelayListDiscoveryResult, RelayListDiscoveryError> {
    let expected_author = hex::encode(participant_public_key);
    let transport_config = ReplaceableDiscoveryConfig {
        authentication_timeout: config.authentication_timeout,
        query_timeout: config.query_timeout,
        minimum_authenticated_relays: config.minimum_authenticated_relays,
        subscription_id: config.subscription_id.clone(),
    };
    let discovered = discover_replaceable_event(
        relay_configs,
        auth_signer,
        participant_public_key,
        NIP65_RELAY_LIST_KIND,
        &transport_config,
        |event| {
            event.pubkey == expected_author
                && parse_nip65_relay_list(event, now, event_limits, relay_limits).is_ok()
        },
    )
    .await
    .map_err(|error| RelayListDiscoveryError::Transport(error.to_string()))?;
    let relay_list = parse_nip65_relay_list(&discovered.event, now, event_limits, relay_limits)
        .map_err(RelayListDiscoveryError::Verification)?;
    if relay_list.public_key != expected_author {
        return Err(RelayListDiscoveryError::UnexpectedAuthor);
    }
    Ok(RelayListDiscoveryResult {
        event: discovered.event,
        relay_list,
        queried_relays: discovered.queried_relays,
        completed_relays: discovered.completed_relays,
    })
}

#[derive(Debug)]
pub enum RelayListDiscoveryError {
    Transport(String),
    Verification(RelayDiscoveryError),
    UnexpectedAuthor,
}

impl fmt::Display for RelayListDiscoveryError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Transport(error) => write!(formatter, "NIP-65 discovery failed: {error}"),
            Self::Verification(error) => {
                write!(
                    formatter,
                    "selected NIP-65 event failed verification: {error}"
                )
            }
            Self::UnexpectedAuthor => {
                formatter.write_str("selected NIP-65 event has an unexpected author")
            }
        }
    }
}

impl Error for RelayListDiscoveryError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Verification(error) => Some(error),
            Self::Transport(_) | Self::UnexpectedAuthor => None,
        }
    }
}
