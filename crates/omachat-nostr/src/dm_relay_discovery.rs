use std::{
    collections::HashSet,
    error::Error,
    fmt,
    time::{Duration, Instant},
};

use serde_json::json;

use crate::{
    auth::RelayAuthSigner,
    discovery::NIP17_DM_RELAY_LIST_KIND,
    event::{EventLimits, SignedEvent},
    inbox::{DmInboxPolicy, verify_dm_inbox},
    pool::{RelayPool, RelayPoolConfig, RelayPoolError},
    relay::{RelayConfig, RelayError, RelayNotification},
};

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DmRelayDiscoveryConfig {
    pub authentication_timeout: Duration,
    pub query_timeout: Duration,
    pub minimum_authenticated_relays: usize,
    pub subscription_id: String,
}

impl Default for DmRelayDiscoveryConfig {
    fn default() -> Self {
        Self {
            authentication_timeout: Duration::from_secs(10),
            query_timeout: Duration::from_secs(10),
            minimum_authenticated_relays: 1,
            subscription_id: "omachat-dm-relay-discovery".into(),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DmRelayDiscoveryResult {
    pub event: SignedEvent,
    pub queried_relays: usize,
    pub completed_relays: usize,
}

pub async fn discover_dm_relay_list(
    mut relay_configs: Vec<RelayConfig>,
    auth_signer: RelayAuthSigner,
    recipient_public_key: &[u8; 32],
    now: u64,
    event_limits: &EventLimits,
    inbox_policy: &DmInboxPolicy,
    config: &DmRelayDiscoveryConfig,
) -> Result<DmRelayDiscoveryResult, DmRelayDiscoveryError> {
    let relay_count = relay_configs.len();
    validate_config(relay_count, config)?;
    for relay in &mut relay_configs {
        relay.auth = Some(auth_signer.clone());
    }
    let mut pool = RelayPool::spawn(
        relay_configs,
        RelayPoolConfig {
            acknowledgement_threshold: 1,
            ..RelayPoolConfig::default()
        },
    )?;
    let expected_authentication_key = hex::encode(auth_signer.public_key());
    let result = discover_inner(
        &mut pool,
        relay_count,
        &expected_authentication_key,
        recipient_public_key,
        now,
        event_limits,
        inbox_policy,
        config,
    )
    .await;
    let shutdown = pool.shutdown().await;
    let discovered = result?;
    if let Some((relay_index, error)) = shutdown
        .into_iter()
        .enumerate()
        .find_map(|(relay_index, result)| result.err().map(|error| (relay_index, error)))
    {
        return Err(DmRelayDiscoveryError::RelayShutdown { relay_index, error });
    }
    Ok(discovered)
}

#[allow(clippy::too_many_arguments)]
async fn discover_inner(
    pool: &mut RelayPool,
    relay_count: usize,
    expected_authentication_key: &str,
    recipient_public_key: &[u8; 32],
    now: u64,
    event_limits: &EventLimits,
    inbox_policy: &DmInboxPolicy,
    config: &DmRelayDiscoveryConfig,
) -> Result<DmRelayDiscoveryResult, DmRelayDiscoveryError> {
    let authentication_deadline = Instant::now() + config.authentication_timeout;
    let mut authenticated = HashSet::new();
    while authenticated.len() < config.minimum_authenticated_relays {
        let notification = next_before(pool, authentication_deadline)
            .await
            .map_err(|_| DmRelayDiscoveryError::AuthenticationTimeout)?;
        match notification.notification {
            RelayNotification::Authenticated { public_key }
                if public_key == expected_authentication_key =>
            {
                authenticated.insert(notification.relay_index);
            }
            RelayNotification::Authenticated { .. } => {
                return Err(DmRelayDiscoveryError::UnexpectedAuthenticatedPrincipal);
            }
            RelayNotification::AuthenticationRejected {
                public_key,
                message,
            } if public_key == expected_authentication_key => {
                return Err(DmRelayDiscoveryError::AuthenticationRejected(message));
            }
            RelayNotification::AuthenticationRejected { .. } => {
                return Err(DmRelayDiscoveryError::UnexpectedAuthenticatedPrincipal);
            }
            _ => {}
        }
    }

    let recipient = hex::encode(recipient_public_key);
    let filters = vec![json!({
        "kinds": [NIP17_DM_RELAY_LIST_KIND],
        "authors": [recipient],
        "limit": 1
    })];
    let subscription_results = pool
        .subscribe(config.subscription_id.clone(), filters)
        .await;
    if subscription_results.len() != relay_count {
        return Err(DmRelayDiscoveryError::PoolStopped);
    }
    let subscribed = subscription_results
        .into_iter()
        .enumerate()
        .filter_map(|(relay_index, result)| result.ok().map(|()| relay_index))
        .collect::<HashSet<_>>();
    if subscribed.is_empty() {
        return Err(DmRelayDiscoveryError::SubscriptionRejected);
    }

    let query_deadline = Instant::now() + config.query_timeout;
    let mut completed = HashSet::new();
    let mut best: Option<SignedEvent> = None;
    while !subscribed.is_subset(&completed) {
        let notification = next_before(pool, query_deadline)
            .await
            .map_err(|_| DmRelayDiscoveryError::QueryTimeout)?;
        if !subscribed.contains(&notification.relay_index) {
            continue;
        }
        match notification.notification {
            RelayNotification::Event {
                subscription_id,
                event,
            } if subscription_id == config.subscription_id => {
                if verify_dm_inbox(
                    &event,
                    recipient_public_key,
                    now,
                    event_limits,
                    inbox_policy,
                )
                .is_ok()
                    && best.as_ref().is_none_or(|current| {
                        (event.created_at, event.id.as_str())
                            > (current.created_at, current.id.as_str())
                    })
                {
                    best = Some(event);
                }
            }
            RelayNotification::EndOfStoredEvents { subscription_id }
                if subscription_id == config.subscription_id =>
            {
                completed.insert(notification.relay_index);
            }
            RelayNotification::Closed {
                subscription_id,
                message,
            } if subscription_id == config.subscription_id => {
                return Err(DmRelayDiscoveryError::SubscriptionClosed(message));
            }
            RelayNotification::AuthenticationRejected {
                public_key,
                message,
            } if public_key == expected_authentication_key => {
                return Err(DmRelayDiscoveryError::AuthenticationRejected(message));
            }
            _ => {}
        }
    }

    let event = best.ok_or(DmRelayDiscoveryError::NoValidMetadata)?;
    Ok(DmRelayDiscoveryResult {
        event,
        queried_relays: subscribed.len(),
        completed_relays: completed.len(),
    })
}

async fn next_before(
    pool: &mut RelayPool,
    deadline: Instant,
) -> Result<crate::pool::PoolNotification, ()> {
    let remaining = deadline.saturating_duration_since(Instant::now());
    if remaining.is_zero() {
        return Err(());
    }
    tokio::time::timeout(remaining, pool.next_notification())
        .await
        .map_err(|_| ())?
        .ok_or(())
}

fn validate_config(
    relay_count: usize,
    config: &DmRelayDiscoveryConfig,
) -> Result<(), DmRelayDiscoveryError> {
    if relay_count == 0
        || config.authentication_timeout.is_zero()
        || config.query_timeout.is_zero()
        || config.minimum_authenticated_relays == 0
        || config.minimum_authenticated_relays > relay_count
        || config.subscription_id.is_empty()
        || config.subscription_id.len() > 64
    {
        return Err(DmRelayDiscoveryError::InvalidConfig);
    }
    Ok(())
}

#[derive(Debug)]
pub enum DmRelayDiscoveryError {
    InvalidConfig,
    Pool(RelayPoolError),
    AuthenticationTimeout,
    AuthenticationRejected(String),
    UnexpectedAuthenticatedPrincipal,
    SubscriptionRejected,
    SubscriptionClosed(String),
    QueryTimeout,
    NoValidMetadata,
    PoolStopped,
    RelayShutdown {
        relay_index: usize,
        error: RelayError,
    },
}

impl From<RelayPoolError> for DmRelayDiscoveryError {
    fn from(error: RelayPoolError) -> Self {
        Self::Pool(error)
    }
}

impl fmt::Display for DmRelayDiscoveryError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidConfig => formatter.write_str("invalid DM relay discovery configuration"),
            Self::Pool(error) => write!(formatter, "DM relay discovery pool failed: {error}"),
            Self::AuthenticationTimeout => {
                formatter.write_str("DM relay discovery authentication timed out")
            }
            Self::AuthenticationRejected(message) => {
                write!(
                    formatter,
                    "DM relay discovery authentication rejected: {message}"
                )
            }
            Self::UnexpectedAuthenticatedPrincipal => {
                formatter.write_str("DM relay discovery authenticated an unexpected principal")
            }
            Self::SubscriptionRejected => {
                formatter.write_str("every DM relay discovery subscription was rejected")
            }
            Self::SubscriptionClosed(message) => {
                write!(
                    formatter,
                    "DM relay discovery subscription closed: {message}"
                )
            }
            Self::QueryTimeout => formatter.write_str("DM relay discovery query timed out"),
            Self::NoValidMetadata => {
                formatter.write_str("DM relay discovery returned no valid recipient metadata")
            }
            Self::PoolStopped => formatter.write_str("DM relay discovery pool stopped"),
            Self::RelayShutdown { relay_index, error } => {
                write!(
                    formatter,
                    "discovery relay {relay_index} shutdown failed: {error}"
                )
            }
        }
    }
}

impl Error for DmRelayDiscoveryError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Pool(error) => Some(error),
            Self::RelayShutdown { error, .. } => Some(error),
            _ => None,
        }
    }
}
