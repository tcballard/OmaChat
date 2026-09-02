use std::{
    collections::BTreeSet,
    error::Error,
    fmt,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use omachat_nostr::{
    auth::RelayAuthSigner,
    event::{EventLimits, SignedEvent},
    relay::{
        RelayAuthenticationPolicy, RelayConfig, RelayConnection, RelayError, RelayNotification,
        RelayRoute,
    },
};
use tokio::{
    sync::{mpsc, oneshot},
    task::{JoinHandle, JoinSet},
    time::{Instant, sleep_until, timeout},
};

use crate::{
    RelayListPublishFuture, RelayListPublisher, RelayListRelayResult, RelayListRelayStatus,
};

const DEFAULT_MAX_PUBLICATION_RELAYS: usize = 16;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NostrRelayListPublisherConfig {
    pub command_capacity: usize,
    pub max_relays: usize,
    pub relay_ready_timeout: Duration,
    pub relay_settle_timeout: Duration,
    pub service_shutdown_timeout: Duration,
    pub connect_timeout: Duration,
    pub response_timeout: Duration,
    pub relay_shutdown_timeout: Duration,
    pub authentication_policy: RelayAuthenticationPolicy,
    pub event_limits: EventLimits,
}

impl Default for NostrRelayListPublisherConfig {
    fn default() -> Self {
        Self {
            command_capacity: 8,
            max_relays: DEFAULT_MAX_PUBLICATION_RELAYS,
            relay_ready_timeout: Duration::from_secs(5),
            relay_settle_timeout: Duration::from_millis(100),
            service_shutdown_timeout: Duration::from_secs(15),
            connect_timeout: Duration::from_secs(5),
            response_timeout: Duration::from_secs(5),
            relay_shutdown_timeout: Duration::from_secs(2),
            authentication_policy: RelayAuthenticationPolicy::AuthenticateWhenChallenged,
            event_limits: EventLimits::default(),
        }
    }
}

pub struct NostrRelayListPublisherService {
    sender: mpsc::Sender<PublisherCommand>,
    task: Option<JoinHandle<()>>,
    shutdown_timeout: Duration,
}

impl NostrRelayListPublisherService {
    pub fn spawn(
        auth_signer: RelayAuthSigner,
        config: NostrRelayListPublisherConfig,
    ) -> Result<Self, NostrRelayListPublisherError> {
        validate_config(&config)?;
        let (sender, receiver) = mpsc::channel(config.command_capacity);
        let shutdown_timeout = config.service_shutdown_timeout;
        let task = tokio::spawn(run_publisher(receiver, auth_signer, config));
        Ok(Self {
            sender,
            task: Some(task),
            shutdown_timeout,
        })
    }

    pub fn handle(&self) -> NostrRelayListPublisherHandle {
        NostrRelayListPublisherHandle {
            sender: self.sender.clone(),
        }
    }

    pub async fn shutdown(mut self) -> Result<(), NostrRelayListPublisherError> {
        let (complete, completed) = oneshot::channel();
        if timeout(
            self.shutdown_timeout,
            self.sender.send(PublisherCommand::Shutdown { complete }),
        )
        .await
        .map_err(|_| NostrRelayListPublisherError::ShutdownTimeout)?
        .is_err()
        {
            return self.join_task().await;
        }
        timeout(self.shutdown_timeout, completed)
            .await
            .map_err(|_| NostrRelayListPublisherError::ShutdownTimeout)?
            .map_err(|_| NostrRelayListPublisherError::Stopped)?;
        self.join_task().await
    }

    async fn join_task(&mut self) -> Result<(), NostrRelayListPublisherError> {
        let Some(mut task) = self.task.take() else {
            return Ok(());
        };
        match timeout(self.shutdown_timeout, &mut task).await {
            Ok(Ok(())) => Ok(()),
            Ok(Err(_)) => Err(NostrRelayListPublisherError::Task),
            Err(_) => {
                task.abort();
                let _ = task.await;
                Err(NostrRelayListPublisherError::ShutdownTimeout)
            }
        }
    }
}

impl Drop for NostrRelayListPublisherService {
    fn drop(&mut self) {
        if let Some(task) = self.task.take() {
            task.abort();
        }
    }
}

#[derive(Clone)]
pub struct NostrRelayListPublisherHandle {
    sender: mpsc::Sender<PublisherCommand>,
}

impl RelayListPublisher for NostrRelayListPublisherHandle {
    fn publish<'a>(
        &'a self,
        event: SignedEvent,
        relay_urls: Vec<String>,
    ) -> RelayListPublishFuture<'a> {
        let sender = self.sender.clone();
        Box::pin(async move {
            let fallback = failed_results(&relay_urls);
            let (respond, response) = oneshot::channel();
            if sender
                .send(PublisherCommand::Publish {
                    event,
                    relay_urls,
                    respond,
                })
                .await
                .is_err()
            {
                return fallback;
            }
            response.await.unwrap_or(fallback)
        })
    }
}

enum PublisherCommand {
    Publish {
        event: SignedEvent,
        relay_urls: Vec<String>,
        respond: oneshot::Sender<Vec<RelayListRelayResult>>,
    },
    Shutdown {
        complete: oneshot::Sender<()>,
    },
}

async fn run_publisher(
    mut receiver: mpsc::Receiver<PublisherCommand>,
    auth_signer: RelayAuthSigner,
    config: NostrRelayListPublisherConfig,
) {
    while let Some(command) = receiver.recv().await {
        match command {
            PublisherCommand::Publish {
                event,
                relay_urls,
                respond,
            } => {
                let results = publish_to_relays(&auth_signer, &config, event, relay_urls).await;
                let _ = respond.send(results);
            }
            PublisherCommand::Shutdown { complete } => {
                let _ = complete.send(());
                break;
            }
        }
    }
}

async fn publish_to_relays(
    auth_signer: &RelayAuthSigner,
    config: &NostrRelayListPublisherConfig,
    event: SignedEvent,
    relay_urls: Vec<String>,
) -> Vec<RelayListRelayResult> {
    if !valid_request(auth_signer, config, &event, &relay_urls) {
        return failed_results(&relay_urls);
    }
    let mut tasks = JoinSet::new();
    for (index, relay_url) in relay_urls.iter().cloned().enumerate() {
        let auth_signer = auth_signer.clone();
        let config = config.clone();
        let event = event.clone();
        tasks.spawn(async move {
            let result = publish_to_relay(&auth_signer, &config, event, relay_url).await;
            (index, result)
        });
    }
    let mut results = failed_results(&relay_urls);
    while let Some(joined) = tasks.join_next().await {
        if let Ok((index, result)) = joined
            && let Some(slot) = results.get_mut(index)
        {
            *slot = result;
        }
    }
    results
}

async fn publish_to_relay(
    auth_signer: &RelayAuthSigner,
    config: &NostrRelayListPublisherConfig,
    event: SignedEvent,
    relay_url: String,
) -> RelayListRelayResult {
    let mut relay_config = RelayConfig::new(relay_url.clone(), RelayRoute::Direct);
    relay_config.auth = Some(auth_signer.clone());
    relay_config.authentication_policy = config.authentication_policy;
    relay_config.connect_timeout = config.connect_timeout;
    relay_config.response_timeout = config.response_timeout;
    relay_config.shutdown_timeout = config.relay_shutdown_timeout;
    relay_config.event_limits = config.event_limits;
    let mut connection = match RelayConnection::spawn(relay_config) {
        Ok(connection) => connection,
        Err(_) => return relay_result(relay_url, RelayListRelayStatus::Failed),
    };
    let status = if wait_until_eligible(
        &mut connection,
        &hex::encode(auth_signer.public_key()),
        config.authentication_policy,
        config.relay_ready_timeout,
        config.relay_settle_timeout,
    )
    .await
    {
        match connection.publish(event.clone()).await {
            Ok(acknowledgement) if acknowledgement.event_id == event.id => {
                RelayListRelayStatus::Acknowledged
            }
            Err(RelayError::PublishRejected(_)) => RelayListRelayStatus::Rejected,
            Ok(_) | Err(_) => RelayListRelayStatus::Failed,
        }
    } else {
        RelayListRelayStatus::Failed
    };
    let _ = connection.shutdown().await;
    relay_result(relay_url, status)
}

async fn wait_until_eligible(
    connection: &mut RelayConnection,
    expected_public_key: &str,
    authentication_policy: RelayAuthenticationPolicy,
    ready_timeout: Duration,
    settle_timeout: Duration,
) -> bool {
    let deadline = Instant::now() + ready_timeout;
    let mut provisionally_eligible = false;
    let mut settle_deadline = None;
    loop {
        if provisionally_eligible && settle_deadline.is_none() {
            settle_deadline = Some((Instant::now() + settle_timeout).min(deadline));
        }
        let wake = settle_deadline.unwrap_or(deadline);
        tokio::select! {
            _ = sleep_until(wake) => return provisionally_eligible,
            notification = connection.next_notification() => {
                match notification {
                    Some(RelayNotification::Connected) => {
                        provisionally_eligible = authentication_policy
                            == RelayAuthenticationPolicy::AuthenticateWhenChallenged;
                        settle_deadline = None;
                    }
                    Some(RelayNotification::AuthChallenge(_)
                        | RelayNotification::Disconnected) => {
                        provisionally_eligible = false;
                        settle_deadline = None;
                    }
                    Some(RelayNotification::Authenticated { public_key }) => {
                        return public_key == expected_public_key;
                    }
                    Some(RelayNotification::AuthenticationRejected { .. }) | None => {
                        return false;
                    }
                    Some(_) => {}
                }
            }
        }
    }
}

fn valid_request(
    auth_signer: &RelayAuthSigner,
    config: &NostrRelayListPublisherConfig,
    event: &SignedEvent,
    relay_urls: &[String],
) -> bool {
    if relay_urls.is_empty() || relay_urls.len() > config.max_relays {
        return false;
    }
    let unique = relay_urls.iter().collect::<BTreeSet<_>>();
    if unique.len() != relay_urls.len() || event.pubkey != hex::encode(auth_signer.public_key()) {
        return false;
    }
    let Ok(now) = SystemTime::now().duration_since(UNIX_EPOCH) else {
        return false;
    };
    event.verify(now.as_secs(), &config.event_limits).is_ok()
}

fn validate_config(
    config: &NostrRelayListPublisherConfig,
) -> Result<(), NostrRelayListPublisherError> {
    if config.command_capacity == 0
        || config.max_relays == 0
        || config.relay_ready_timeout.is_zero()
        || config.relay_settle_timeout.is_zero()
        || config.service_shutdown_timeout.is_zero()
        || config.connect_timeout.is_zero()
        || config.response_timeout.is_zero()
        || config.relay_shutdown_timeout.is_zero()
    {
        return Err(NostrRelayListPublisherError::InvalidConfig);
    }
    Ok(())
}

fn failed_results(relay_urls: &[String]) -> Vec<RelayListRelayResult> {
    relay_urls
        .iter()
        .cloned()
        .map(|relay_url| relay_result(relay_url, RelayListRelayStatus::Failed))
        .collect()
}

fn relay_result(relay_url: String, status: RelayListRelayStatus) -> RelayListRelayResult {
    RelayListRelayResult { relay_url, status }
}

#[derive(Debug)]
pub enum NostrRelayListPublisherError {
    InvalidConfig,
    Stopped,
    Task,
    ShutdownTimeout,
}

impl fmt::Display for NostrRelayListPublisherError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidConfig => formatter.write_str("invalid NIP-65 publisher configuration"),
            Self::Stopped => formatter.write_str("NIP-65 publisher stopped"),
            Self::Task => formatter.write_str("NIP-65 publisher task failed"),
            Self::ShutdownTimeout => formatter.write_str("NIP-65 publisher shutdown timed out"),
        }
    }
}

impl Error for NostrRelayListPublisherError {}
