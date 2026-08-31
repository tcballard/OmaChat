//! Deterministic bounded policy across independent relay connections.

use crate::{
    event::SignedEvent,
    relay::{
        PublishAcknowledgement, RelayConfig, RelayConnection, RelayError, RelayHealth,
        RelayNotification,
    },
};
use futures_util::{StreamExt, future::join_all, stream::FuturesUnordered};
use serde_json::Value;
use std::{
    collections::{HashMap, HashSet, VecDeque},
    error::Error,
    fmt,
    time::{Duration, Instant},
};

/// Bounded relay-pool policy.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RelayPoolConfig {
    pub acknowledgement_threshold: usize,
    pub dedup_capacity: usize,
    pub dedup_ttl: Duration,
}

impl Default for RelayPoolConfig {
    fn default() -> Self {
        Self {
            acknowledgement_threshold: 1,
            dedup_capacity: 10_000,
            dedup_ttl: Duration::from_secs(5 * 60),
        }
    }
}

/// One relay's result for a pool publish.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RelayPublishOutcome {
    pub relay_index: usize,
    pub result: Result<PublishAcknowledgement, RelayError>,
}

/// Publish results after the configured acknowledgement threshold passed.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PoolPublishResult {
    pub accepted: usize,
    pub attempted: usize,
    pub outcomes: Vec<RelayPublishOutcome>,
}

/// A relay notification with its source index. Authenticated events are
/// deduplicated by event ID before being returned.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PoolNotification {
    pub relay_index: usize,
    pub notification: RelayNotification,
}

/// Pool of independent connection actors.
pub struct RelayPool {
    connections: Vec<RelayConnection>,
    config: RelayPoolConfig,
    subscriptions: HashMap<String, Vec<Value>>,
    subscription_sync: Vec<HashSet<String>>,
    seen: HashSet<String>,
    seen_order: VecDeque<(Instant, String)>,
    closed_notifications: HashSet<usize>,
}

impl RelayPool {
    /// Spawn every configured connection. The threshold must be satisfiable by
    /// the configured relay count and all dedup bounds must be non-zero.
    pub fn spawn(
        relay_configs: Vec<RelayConfig>,
        config: RelayPoolConfig,
    ) -> Result<Self, RelayPoolError> {
        if relay_configs.is_empty() {
            return Err(RelayPoolError::InvalidConfig(
                "at least one relay is required",
            ));
        }
        if config.acknowledgement_threshold == 0
            || config.acknowledgement_threshold > relay_configs.len()
        {
            return Err(RelayPoolError::InvalidConfig(
                "acknowledgement threshold must fit the relay count",
            ));
        }
        if config.dedup_capacity == 0 || config.dedup_ttl.is_zero() {
            return Err(RelayPoolError::InvalidConfig(
                "dedup capacity and TTL must be non-zero",
            ));
        }
        let connections = relay_configs
            .into_iter()
            .map(RelayConnection::spawn)
            .collect::<Result<Vec<_>, _>>()?;
        let subscription_sync = (0..connections.len()).map(|_| HashSet::new()).collect();
        Ok(Self {
            connections,
            config,
            subscriptions: HashMap::new(),
            subscription_sync,
            seen: HashSet::new(),
            seen_order: VecDeque::new(),
            closed_notifications: HashSet::new(),
        })
    }

    /// Snapshot relay health in stable configuration order.
    #[must_use]
    pub fn health(&self) -> Vec<RelayHealth> {
        self.connections
            .iter()
            .map(|connection| *connection.health().borrow())
            .collect()
    }

    /// Publish only to connections currently reporting healthy. A failed or
    /// flapping relay cannot prevent healthy acknowledgements from completing.
    pub async fn publish(&self, event: SignedEvent) -> Result<PoolPublishResult, RelayPoolError> {
        let attempts = self
            .connections
            .iter()
            .enumerate()
            .filter(|(_, connection)| *connection.health().borrow() == RelayHealth::Connected)
            .map(|(relay_index, connection)| {
                let event = event.clone();
                async move {
                    RelayPublishOutcome {
                        relay_index,
                        result: connection.publish(event).await,
                    }
                }
            });
        let outcomes = join_all(attempts).await;
        let attempted = outcomes.len();
        let accepted = outcomes
            .iter()
            .filter(|outcome| outcome.result.is_ok())
            .count();
        if accepted < self.config.acknowledgement_threshold {
            return Err(RelayPoolError::AcknowledgementThreshold {
                accepted,
                required: self.config.acknowledgement_threshold,
                attempted,
            });
        }
        Ok(PoolPublishResult {
            accepted,
            attempted,
            outcomes,
        })
    }

    /// Store and send one logical subscription to every relay. Repeating an
    /// identical subscription is a no-op; changing its filters replaces it.
    pub async fn subscribe(
        &mut self,
        subscription_id: String,
        filters: Vec<Value>,
    ) -> Vec<Result<(), RelayError>> {
        if self.subscriptions.get(&subscription_id) == Some(&filters)
            && self
                .subscription_sync
                .iter()
                .all(|synced| synced.contains(&subscription_id))
        {
            return Vec::new();
        }
        for synced in &mut self.subscription_sync {
            synced.remove(&subscription_id);
        }
        self.subscriptions
            .insert(subscription_id.clone(), filters.clone());
        let results = join_all(
            self.connections
                .iter()
                .map(|connection| connection.subscribe(subscription_id.clone(), filters.clone())),
        )
        .await;
        for (relay_index, result) in results.iter().enumerate() {
            if result.is_ok() {
                self.subscription_sync[relay_index].insert(subscription_id.clone());
            }
        }
        results
    }

    /// Close one logical subscription on every relay.
    pub async fn close_subscription(
        &mut self,
        subscription_id: String,
    ) -> Vec<Result<(), RelayError>> {
        self.subscriptions.remove(&subscription_id);
        for synced in &mut self.subscription_sync {
            synced.remove(&subscription_id);
        }
        join_all(
            self.connections
                .iter()
                .map(|connection| connection.close_subscription(subscription_id.clone())),
        )
        .await
    }

    /// Receive the next notification from any relay. Duplicate authenticated
    /// events inside the bounded TTL cache are consumed but not returned.
    pub async fn next_notification(&mut self) -> Option<PoolNotification> {
        loop {
            let connection_count = self.connections.len();
            let mut pending = FuturesUnordered::new();
            for (relay_index, connection) in self.connections.iter_mut().enumerate() {
                if !self.closed_notifications.contains(&relay_index) {
                    pending
                        .push(async move { (relay_index, connection.next_notification().await) });
                }
            }
            let next = pending.next().await?;
            drop(pending);
            let (relay_index, notification) = next;
            let Some(notification) = notification else {
                self.closed_notifications.insert(relay_index);
                if self.closed_notifications.len() == connection_count {
                    return None;
                }
                continue;
            };
            if let RelayNotification::Connected = notification {
                self.closed_notifications.remove(&relay_index);
                let missing = self
                    .subscriptions
                    .iter()
                    .filter(|(id, _)| !self.subscription_sync[relay_index].contains(*id))
                    .map(|(id, filters)| (id.clone(), filters.clone()))
                    .collect::<Vec<_>>();
                for (subscription_id, filters) in missing {
                    if self.connections[relay_index]
                        .subscribe(subscription_id.clone(), filters)
                        .await
                        .is_ok()
                    {
                        self.subscription_sync[relay_index].insert(subscription_id);
                    }
                }
            }
            if let RelayNotification::Event { event, .. } = &notification
                && !self.remember_event(&event.id)
            {
                continue;
            }
            return Some(PoolNotification {
                relay_index,
                notification,
            });
        }
    }

    /// Shut every connection down concurrently and await all owned tasks.
    pub async fn shutdown(self) -> Vec<Result<(), RelayError>> {
        join_all(self.connections.into_iter().map(RelayConnection::shutdown)).await
    }

    fn remember_event(&mut self, id: &str) -> bool {
        let now = Instant::now();
        while let Some((seen_at, oldest)) = self.seen_order.front() {
            if now.duration_since(*seen_at) < self.config.dedup_ttl {
                break;
            }
            self.seen.remove(oldest);
            self.seen_order.pop_front();
        }
        if self.seen.contains(id) {
            return false;
        }
        while self.seen.len() >= self.config.dedup_capacity {
            let Some((_, oldest)) = self.seen_order.pop_front() else {
                break;
            };
            self.seen.remove(&oldest);
        }
        self.seen.insert(id.to_owned());
        self.seen_order.push_back((now, id.to_owned()));
        true
    }
}

/// Relay-pool policy and quorum failures.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum RelayPoolError {
    InvalidConfig(&'static str),
    Connection(RelayError),
    AcknowledgementThreshold {
        accepted: usize,
        required: usize,
        attempted: usize,
    },
}

impl fmt::Display for RelayPoolError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidConfig(message) => {
                write!(formatter, "invalid relay pool config: {message}")
            }
            Self::Connection(error) => write!(formatter, "relay connection failed: {error}"),
            Self::AcknowledgementThreshold {
                accepted,
                required,
                attempted,
            } => write!(
                formatter,
                "relay publish received {accepted}/{required} required acknowledgements across {attempted} healthy relays"
            ),
        }
    }
}

impl Error for RelayPoolError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Connection(error) => Some(error),
            _ => None,
        }
    }
}

impl From<RelayError> for RelayPoolError {
    fn from(error: RelayError) -> Self {
        Self::Connection(error)
    }
}
