use std::{
    collections::{HashMap, HashSet},
    error::Error,
    fmt,
    time::{Duration, Instant},
};

use k256::schnorr::VerifyingKey as SchnorrVerifyingKey;
use serde_json::json;

use crate::{
    auth::RelayAuthSigner,
    event::SignedEvent,
    pool::{RelayPool, RelayPoolConfig, RelayPoolError},
    relay::{RelayAuthenticationPolicy, RelayConfig, RelayError, RelayNotification},
};

const MAX_DISCOVERY_RELAYS: usize = 16;

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct ReplaceableDiscoveryConfig {
    pub authentication_timeout: Duration,
    pub authentication_policy: RelayAuthenticationPolicy,
    pub challenge_settle_timeout: Duration,
    pub query_timeout: Duration,
    pub minimum_ready_relays: usize,
    pub subscription_id: String,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct ReplaceableDiscoveryResult {
    pub event: SignedEvent,
    pub queried_relays: usize,
    pub completed_relays: usize,
}

pub(crate) async fn discover_replaceable_event<F>(
    mut relay_configs: Vec<RelayConfig>,
    auth_signer: RelayAuthSigner,
    author_public_key: &[u8; 32],
    event_kind: u32,
    config: &ReplaceableDiscoveryConfig,
    mut validate_event: F,
) -> Result<ReplaceableDiscoveryResult, ReplaceableDiscoveryError>
where
    F: FnMut(&SignedEvent) -> bool,
{
    let relay_count = relay_configs.len();
    validate_config(relay_count, author_public_key, config)?;
    for relay in &mut relay_configs {
        relay.auth = Some(auth_signer.clone());
        relay.authentication_policy = config.authentication_policy;
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
        author_public_key,
        event_kind,
        config,
        &mut validate_event,
    )
    .await;
    let shutdown = pool.shutdown().await;
    let discovered = result?;
    if let Some((relay_index, error)) = shutdown
        .into_iter()
        .enumerate()
        .find_map(|(relay_index, result)| result.err().map(|error| (relay_index, error)))
    {
        return Err(ReplaceableDiscoveryError::RelayShutdown { relay_index, error });
    }
    Ok(discovered)
}

#[allow(clippy::too_many_arguments)]
async fn discover_inner<F>(
    pool: &mut RelayPool,
    relay_count: usize,
    expected_authentication_key: &str,
    author_public_key: &[u8; 32],
    event_kind: u32,
    config: &ReplaceableDiscoveryConfig,
    validate_event: &mut F,
) -> Result<ReplaceableDiscoveryResult, ReplaceableDiscoveryError>
where
    F: FnMut(&SignedEvent) -> bool,
{
    await_relay_readiness(pool, expected_authentication_key, config).await?;

    let filters = vec![json!({
        "kinds": [event_kind],
        "authors": [hex::encode(author_public_key)],
        "limit": 1
    })];
    let subscription_results = pool
        .subscribe(config.subscription_id.clone(), filters)
        .await;
    if subscription_results.len() != relay_count {
        return Err(ReplaceableDiscoveryError::PoolStopped);
    }
    let subscribed = subscription_results
        .into_iter()
        .enumerate()
        .filter_map(|(relay_index, result)| result.ok().map(|()| relay_index))
        .collect::<HashSet<_>>();
    if subscribed.is_empty() {
        return Err(ReplaceableDiscoveryError::SubscriptionRejected);
    }
    if subscribed.len() < config.minimum_ready_relays {
        return Err(ReplaceableDiscoveryError::InsufficientRelaySubscriptions {
            required: config.minimum_ready_relays,
            actual: subscribed.len(),
        });
    }

    let query_deadline = Instant::now() + config.query_timeout;
    let mut completed = HashSet::new();
    let mut best: Option<SignedEvent> = None;
    while !subscribed.is_subset(&completed) {
        let notification = next_before(pool, query_deadline)
            .await
            .map_err(|_| ReplaceableDiscoveryError::QueryTimeout)?;
        if !subscribed.contains(&notification.relay_index) {
            continue;
        }
        match notification.notification {
            RelayNotification::Event {
                subscription_id,
                event,
            } if subscription_id == config.subscription_id => {
                if validate_event(&event)
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
                return Err(ReplaceableDiscoveryError::SubscriptionClosed(message));
            }
            RelayNotification::AuthenticationRejected {
                public_key,
                message,
            } if public_key == expected_authentication_key => {
                return Err(ReplaceableDiscoveryError::AuthenticationRejected(message));
            }
            _ => {}
        }
    }

    Ok(ReplaceableDiscoveryResult {
        event: best.ok_or(ReplaceableDiscoveryError::NoValidEvent)?,
        queried_relays: subscribed.len(),
        completed_relays: completed.len(),
    })
}

async fn await_relay_readiness(
    pool: &mut RelayPool,
    expected_authentication_key: &str,
    config: &ReplaceableDiscoveryConfig,
) -> Result<(), ReplaceableDiscoveryError> {
    match config.authentication_policy {
        RelayAuthenticationPolicy::RequireWhenConfigured => {
            await_required_authentication(pool, expected_authentication_key, config).await
        }
        RelayAuthenticationPolicy::AuthenticateWhenChallenged => {
            await_challenge_driven_readiness(pool, expected_authentication_key, config).await
        }
    }
}

async fn await_required_authentication(
    pool: &mut RelayPool,
    expected_authentication_key: &str,
    config: &ReplaceableDiscoveryConfig,
) -> Result<(), ReplaceableDiscoveryError> {
    let deadline = Instant::now() + config.authentication_timeout;
    let mut authenticated = HashSet::new();
    while authenticated.len() < config.minimum_ready_relays {
        let notification = next_before(pool, deadline)
            .await
            .map_err(|_| ReplaceableDiscoveryError::AuthenticationTimeout)?;
        match notification.notification {
            RelayNotification::Authenticated { public_key }
                if public_key == expected_authentication_key =>
            {
                authenticated.insert(notification.relay_index);
            }
            RelayNotification::Authenticated { .. } => {
                return Err(ReplaceableDiscoveryError::UnexpectedAuthenticatedPrincipal);
            }
            RelayNotification::AuthenticationRejected {
                public_key,
                message,
            } if public_key == expected_authentication_key => {
                return Err(ReplaceableDiscoveryError::AuthenticationRejected(message));
            }
            RelayNotification::AuthenticationRejected { .. } => {
                return Err(ReplaceableDiscoveryError::UnexpectedAuthenticatedPrincipal);
            }
            _ => {}
        }
    }
    Ok(())
}

async fn await_challenge_driven_readiness(
    pool: &mut RelayPool,
    expected_authentication_key: &str,
    config: &ReplaceableDiscoveryConfig,
) -> Result<(), ReplaceableDiscoveryError> {
    let authentication_deadline = Instant::now() + config.authentication_timeout;
    let mut connected_at = HashMap::<usize, Instant>::new();
    let mut challenged = HashSet::new();
    let mut authenticated = HashSet::new();
    loop {
        let now = Instant::now();
        let ready = connected_at
            .iter()
            .filter(|(relay_index, connected)| {
                authenticated.contains(*relay_index)
                    || (!challenged.contains(*relay_index)
                        && now.saturating_duration_since(**connected)
                            >= config.challenge_settle_timeout)
            })
            .count();
        if ready >= config.minimum_ready_relays {
            return Ok(());
        }
        if now >= authentication_deadline {
            return Err(ReplaceableDiscoveryError::AuthenticationTimeout);
        }
        let next_settle = connected_at
            .iter()
            .filter(|(relay_index, _)| {
                !challenged.contains(*relay_index) && !authenticated.contains(*relay_index)
            })
            .map(|(_, connected)| *connected + config.challenge_settle_timeout)
            .min()
            .unwrap_or(authentication_deadline);
        let wait_deadline = next_settle.min(authentication_deadline);
        let notification = match next_before(pool, wait_deadline).await {
            Ok(notification) => notification,
            Err(()) => continue,
        };
        let relay_index = notification.relay_index;
        match notification.notification {
            RelayNotification::Connected => {
                connected_at.insert(relay_index, Instant::now());
            }
            RelayNotification::Disconnected => {
                connected_at.remove(&relay_index);
                challenged.remove(&relay_index);
                authenticated.remove(&relay_index);
            }
            RelayNotification::AuthChallenge(_) => {
                challenged.insert(relay_index);
            }
            RelayNotification::Authenticated { public_key }
                if public_key == expected_authentication_key =>
            {
                connected_at.entry(relay_index).or_insert_with(Instant::now);
                challenged.remove(&relay_index);
                authenticated.insert(relay_index);
            }
            RelayNotification::Authenticated { .. } => {
                return Err(ReplaceableDiscoveryError::UnexpectedAuthenticatedPrincipal);
            }
            RelayNotification::AuthenticationRejected {
                public_key,
                message,
            } if public_key == expected_authentication_key => {
                return Err(ReplaceableDiscoveryError::AuthenticationRejected(message));
            }
            RelayNotification::AuthenticationRejected { .. } => {
                return Err(ReplaceableDiscoveryError::UnexpectedAuthenticatedPrincipal);
            }
            _ => {}
        }
    }
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
    author_public_key: &[u8; 32],
    config: &ReplaceableDiscoveryConfig,
) -> Result<(), ReplaceableDiscoveryError> {
    if relay_count == 0
        || relay_count > MAX_DISCOVERY_RELAYS
        || SchnorrVerifyingKey::from_bytes(author_public_key).is_err()
        || config.authentication_timeout.is_zero()
        || config.challenge_settle_timeout.is_zero()
        || config.query_timeout.is_zero()
        || config.minimum_ready_relays == 0
        || config.minimum_ready_relays > relay_count
        || config.subscription_id.is_empty()
        || config.subscription_id.len() > 64
    {
        return Err(ReplaceableDiscoveryError::InvalidConfig);
    }
    Ok(())
}

#[derive(Debug)]
pub(crate) enum ReplaceableDiscoveryError {
    InvalidConfig,
    Pool(RelayPoolError),
    AuthenticationTimeout,
    AuthenticationRejected(String),
    UnexpectedAuthenticatedPrincipal,
    SubscriptionRejected,
    InsufficientRelaySubscriptions {
        required: usize,
        actual: usize,
    },
    SubscriptionClosed(String),
    QueryTimeout,
    NoValidEvent,
    PoolStopped,
    RelayShutdown {
        relay_index: usize,
        error: RelayError,
    },
}

impl From<RelayPoolError> for ReplaceableDiscoveryError {
    fn from(error: RelayPoolError) -> Self {
        Self::Pool(error)
    }
}

impl fmt::Display for ReplaceableDiscoveryError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidConfig => {
                formatter.write_str("invalid replaceable-event discovery configuration")
            }
            Self::Pool(error) => write!(
                formatter,
                "replaceable-event discovery pool failed: {error}"
            ),
            Self::AuthenticationTimeout => {
                formatter.write_str("replaceable-event discovery authentication timed out")
            }
            Self::AuthenticationRejected(message) => {
                write!(
                    formatter,
                    "replaceable-event authentication rejected: {message}"
                )
            }
            Self::UnexpectedAuthenticatedPrincipal => formatter
                .write_str("replaceable-event discovery authenticated an unexpected principal"),
            Self::SubscriptionRejected => {
                formatter.write_str("every replaceable-event discovery subscription was rejected")
            }
            Self::InsufficientRelaySubscriptions { required, actual } => write!(
                formatter,
                "replaceable-event discovery requires {required} relay subscriptions, got {actual}"
            ),
            Self::SubscriptionClosed(message) => {
                write!(
                    formatter,
                    "replaceable-event discovery subscription closed: {message}"
                )
            }
            Self::QueryTimeout => {
                formatter.write_str("replaceable-event discovery query timed out")
            }
            Self::NoValidEvent => {
                formatter.write_str("discovery returned no valid replaceable event")
            }
            Self::PoolStopped => formatter.write_str("replaceable-event discovery pool stopped"),
            Self::RelayShutdown { relay_index, error } => {
                write!(
                    formatter,
                    "discovery relay {relay_index} shutdown failed: {error}"
                )
            }
        }
    }
}

impl Error for ReplaceableDiscoveryError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Pool(error) => Some(error),
            Self::RelayShutdown { error, .. } => Some(error),
            _ => None,
        }
    }
}
