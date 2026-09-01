use std::{
    collections::{HashMap, HashSet},
    error::Error,
    fmt,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    time::Duration,
};

use omachat_nostr::{
    auth::RelayAuthSigner,
    event::SignedEvent,
    pool::{PoolPublishResult, RelayPool, RelayPoolConfig, RelayPoolError},
    relay::{RelayConfig, RelayNotification, RelayRoute},
};
use tokio::{
    sync::{mpsc, oneshot, watch},
    task::JoinHandle,
    time::{Instant, sleep_until, timeout},
};

use crate::PendingProfilePublication;

const INBOUND_POLL: Duration = Duration::from_millis(100);

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProfilePublicationServiceConfig {
    pub command_capacity: usize,
    pub authentication_wait_timeout: Duration,
    pub authentication_settle_timeout: Duration,
}

impl Default for ProfilePublicationServiceConfig {
    fn default() -> Self {
        Self {
            command_capacity: 8,
            authentication_wait_timeout: Duration::from_secs(10),
            authentication_settle_timeout: Duration::from_millis(100),
        }
    }
}

#[derive(Clone)]
pub struct ProfilePublicationHandle {
    commands: mpsc::Sender<Command>,
    relay_urls: Arc<Vec<String>>,
    expected_public_key: Arc<String>,
    accepting: Arc<AtomicBool>,
    stop: watch::Sender<bool>,
    stopped: watch::Receiver<bool>,
}

impl ProfilePublicationHandle {
    /// Publish the exact pending event only to relays lacking durable ACKs.
    pub async fn publish(
        &self,
        pending: &PendingProfilePublication,
    ) -> Result<PoolPublishResult, ProfilePublicationServiceError> {
        if !self.accepting.load(Ordering::Acquire) {
            return Err(ProfilePublicationServiceError::Stopped);
        }
        if pending.relay_urls() != self.relay_urls.as_slice() {
            return Err(ProfilePublicationServiceError::PolicyMismatch);
        }
        if &pending.event().pubkey != self.expected_public_key.as_ref() {
            return Err(ProfilePublicationServiceError::PolicyMismatch);
        }
        let relay_indices = pending
            .remaining_relay_indices()
            .into_iter()
            .collect::<HashSet<_>>();
        if relay_indices.is_empty() {
            return Err(ProfilePublicationServiceError::PolicyMismatch);
        }
        let mut stop = self.stop.subscribe();
        let (response, result) = oneshot::channel();
        tokio::select! {
            biased;
            changed = stop.changed() => {
                let _ = changed;
                return Err(ProfilePublicationServiceError::Stopped);
            }
            sent = self.commands.send(Command::Publish {
                event: pending.event().clone(),
                relay_indices,
                response,
            }) => {
                sent.map_err(|_| ProfilePublicationServiceError::Stopped)?;
            }
        }
        tokio::select! {
            biased;
            changed = stop.changed() => {
                let _ = changed;
                Err(ProfilePublicationServiceError::Stopped)
            }
            received = result => {
                received.map_err(|_| ProfilePublicationServiceError::Stopped)?
            }
        }
    }

    /// Stop accepting work and wait until every relay actor has terminated.
    pub async fn quiesce(&self) {
        self.accepting.store(false, Ordering::Release);
        self.stop.send_replace(true);
        let mut stopped = self.stopped.clone();
        while !*stopped.borrow() {
            if stopped.changed().await.is_err() {
                break;
            }
        }
    }
}

pub struct ProfilePublicationService {
    handle: ProfilePublicationHandle,
    task: Option<JoinHandle<Result<(), RelayPoolError>>>,
}

impl ProfilePublicationService {
    pub fn spawn(
        relay_urls: &[String],
        auth_signer: RelayAuthSigner,
        config: ProfilePublicationServiceConfig,
    ) -> Result<Self, ProfilePublicationServiceError> {
        if relay_urls.is_empty()
            || config.command_capacity == 0
            || config.authentication_wait_timeout.is_zero()
            || config.authentication_settle_timeout.is_zero()
        {
            return Err(ProfilePublicationServiceError::InvalidConfig);
        }
        let expected_public_key = Arc::new(hex::encode(auth_signer.public_key()));
        let relay_configs = relay_urls
            .iter()
            .cloned()
            .map(|url| {
                let mut relay = RelayConfig::new(url, RelayRoute::Direct);
                relay.auth = Some(auth_signer.clone());
                relay
            })
            .collect();
        let pool = RelayPool::spawn(
            relay_configs,
            RelayPoolConfig {
                acknowledgement_threshold: 1,
                ..RelayPoolConfig::default()
            },
        )
        .map_err(ProfilePublicationServiceError::Pool)?;
        let (commands, receiver) = mpsc::channel(config.command_capacity);
        let accepting = Arc::new(AtomicBool::new(true));
        let (stop, stop_receiver) = watch::channel(false);
        let (stopped_sender, stopped) = watch::channel(false);
        let handle = ProfilePublicationHandle {
            commands,
            relay_urls: Arc::new(relay_urls.to_vec()),
            expected_public_key: Arc::clone(&expected_public_key),
            accepting: Arc::clone(&accepting),
            stop,
            stopped,
        };
        let task = tokio::spawn(run(
            pool,
            receiver,
            stop_receiver,
            accepting,
            stopped_sender,
            AuthenticatedRelayState::new((*expected_public_key).clone()),
            config,
        ));
        Ok(Self {
            handle,
            task: Some(task),
        })
    }

    #[must_use]
    pub fn handle(&self) -> ProfilePublicationHandle {
        self.handle.clone()
    }

    pub async fn shutdown(mut self) -> Result<(), ProfilePublicationServiceError> {
        self.handle.quiesce().await;
        let result = self
            .task
            .as_mut()
            .expect("profile publication task remains owned")
            .await
            .map_err(|_| ProfilePublicationServiceError::Task)?;
        self.task.take();
        result.map_err(ProfilePublicationServiceError::Pool)
    }
}

impl Drop for ProfilePublicationService {
    fn drop(&mut self) {
        if let Some(task) = &self.task {
            task.abort();
        }
    }
}

enum Command {
    Publish {
        event: SignedEvent,
        relay_indices: HashSet<usize>,
        response: oneshot::Sender<Result<PoolPublishResult, ProfilePublicationServiceError>>,
    },
}

async fn run(
    mut pool: RelayPool,
    mut commands: mpsc::Receiver<Command>,
    mut stop: watch::Receiver<bool>,
    accepting: Arc<AtomicBool>,
    stopped: watch::Sender<bool>,
    mut authentication: AuthenticatedRelayState,
    config: ProfilePublicationServiceConfig,
) -> Result<(), RelayPoolError> {
    run_until_stopped(
        &mut pool,
        &mut commands,
        &mut stop,
        &mut authentication,
        config.authentication_wait_timeout,
        config.authentication_settle_timeout,
    )
    .await;
    accepting.store(false, Ordering::Release);
    commands.close();
    while commands.try_recv().is_ok() {}
    let result = pool
        .shutdown()
        .await
        .into_iter()
        .find_map(Result::err)
        .map_or(Ok(()), |error| Err(error.into()));
    stopped.send_replace(true);
    result
}

async fn run_until_stopped(
    pool: &mut RelayPool,
    commands: &mut mpsc::Receiver<Command>,
    stop: &mut watch::Receiver<bool>,
    authentication: &mut AuthenticatedRelayState,
    authentication_wait_timeout: Duration,
    authentication_settle_timeout: Duration,
) {
    loop {
        tokio::select! {
            biased;
            _ = wait_for_stop(stop) => return,
            command = commands.recv() => {
                let Some(command) = command else { return };
                if run_command(
                    pool,
                    command,
                    stop,
                    authentication,
                    authentication_wait_timeout,
                    authentication_settle_timeout,
                ).await {
                    return;
                }
            }
            notification = timeout(INBOUND_POLL, pool.next_notification()) => {
                if let Ok(Some(notification)) = notification {
                    authentication.apply(notification.relay_index, &notification.notification);
                }
            }
        }
    }
}

async fn run_command(
    pool: &mut RelayPool,
    command: Command,
    stop: &mut watch::Receiver<bool>,
    authentication: &mut AuthenticatedRelayState,
    authentication_wait_timeout: Duration,
    authentication_settle_timeout: Duration,
) -> bool {
    match command {
        Command::Publish {
            event,
            relay_indices,
            response,
        } => {
            let result = wait_for_target_authentication(
                pool,
                &relay_indices,
                stop,
                authentication,
                authentication_wait_timeout,
                authentication_settle_timeout,
            )
            .await;
            let result = match result {
                Ok(authenticated_indices) => {
                    tokio::select! {
                        biased;
                        _ = wait_for_stop(stop) => return true,
                        result = pool.publish_to_indices(event, &authenticated_indices, 1) => {
                            result.map_err(ProfilePublicationServiceError::Pool)
                        }
                    }
                }
                Err(error) => Err(error),
            };
            let _ = response.send(result);
            false
        }
    }
}

async fn wait_for_target_authentication(
    pool: &mut RelayPool,
    relay_indices: &HashSet<usize>,
    stop: &mut watch::Receiver<bool>,
    authentication: &mut AuthenticatedRelayState,
    authentication_wait_timeout: Duration,
    authentication_settle_timeout: Duration,
) -> Result<HashSet<usize>, ProfilePublicationServiceError> {
    let deadline = Instant::now() + authentication_wait_timeout;
    let mut settle_deadline = None;
    loop {
        let authenticated = authentication.eligible(relay_indices);
        if authenticated.len() == relay_indices.len() {
            return Ok(authenticated);
        }
        if authenticated.is_empty() {
            settle_deadline = None;
        } else if settle_deadline.is_none() {
            settle_deadline = Some((Instant::now() + authentication_settle_timeout).min(deadline));
        }
        let wake = settle_deadline.unwrap_or(deadline);
        tokio::select! {
            biased;
            _ = wait_for_stop(stop) => return Err(ProfilePublicationServiceError::Stopped),
            _ = sleep_until(wake) => {
                let authenticated = authentication.eligible(relay_indices);
                return if authenticated.is_empty() {
                    Err(authentication.failure(relay_indices))
                } else {
                    Ok(authenticated)
                };
            }
            notification = pool.next_notification() => {
                let Some(notification) = notification else {
                    return Err(ProfilePublicationServiceError::Stopped);
                };
                authentication.apply(notification.relay_index, &notification.notification);
            }
        }
    }
}

#[derive(Clone, Debug)]
enum RelayAuthenticationFailure {
    Rejected(String),
    UnexpectedPrincipal,
}

#[derive(Debug)]
struct AuthenticatedRelayState {
    expected_public_key: String,
    authenticated: HashSet<usize>,
    failures: HashMap<usize, RelayAuthenticationFailure>,
}

impl AuthenticatedRelayState {
    fn new(expected_public_key: String) -> Self {
        Self {
            expected_public_key,
            authenticated: HashSet::new(),
            failures: HashMap::new(),
        }
    }

    fn apply(&mut self, relay_index: usize, notification: &RelayNotification) {
        match notification {
            RelayNotification::Authenticated { public_key }
                if public_key == &self.expected_public_key =>
            {
                self.authenticated.insert(relay_index);
                self.failures.remove(&relay_index);
            }
            RelayNotification::Authenticated { .. } => {
                self.authenticated.remove(&relay_index);
                self.failures
                    .insert(relay_index, RelayAuthenticationFailure::UnexpectedPrincipal);
            }
            RelayNotification::AuthenticationRejected {
                public_key,
                message,
            } if public_key == &self.expected_public_key => {
                self.authenticated.remove(&relay_index);
                self.failures.insert(
                    relay_index,
                    RelayAuthenticationFailure::Rejected(message.clone()),
                );
            }
            RelayNotification::AuthenticationRejected { .. } => {
                self.authenticated.remove(&relay_index);
                self.failures
                    .insert(relay_index, RelayAuthenticationFailure::UnexpectedPrincipal);
            }
            RelayNotification::Connected
            | RelayNotification::Disconnected
            | RelayNotification::AuthChallenge(_) => {
                self.authenticated.remove(&relay_index);
                self.failures.remove(&relay_index);
            }
            _ => {}
        }
    }

    fn eligible(&self, relay_indices: &HashSet<usize>) -> HashSet<usize> {
        self.authenticated
            .intersection(relay_indices)
            .copied()
            .collect()
    }

    fn failure(&self, relay_indices: &HashSet<usize>) -> ProfilePublicationServiceError {
        let mut indices = relay_indices.iter().copied().collect::<Vec<_>>();
        indices.sort_unstable();
        for relay_index in &indices {
            if matches!(
                self.failures.get(relay_index),
                Some(RelayAuthenticationFailure::UnexpectedPrincipal)
            ) {
                return ProfilePublicationServiceError::UnexpectedAuthenticatedPrincipal;
            }
        }
        for relay_index in indices {
            if let Some(RelayAuthenticationFailure::Rejected(message)) =
                self.failures.get(&relay_index)
            {
                return ProfilePublicationServiceError::AuthenticationRejected(message.clone());
            }
        }
        ProfilePublicationServiceError::NoAuthenticatedRelay
    }
}

async fn wait_for_stop(stop: &mut watch::Receiver<bool>) {
    loop {
        if *stop.borrow() {
            return;
        }
        if stop.changed().await.is_err() {
            return;
        }
    }
}

#[derive(Debug)]
pub enum ProfilePublicationServiceError {
    Pool(RelayPoolError),
    InvalidConfig,
    PolicyMismatch,
    NoAuthenticatedRelay,
    AuthenticationRejected(String),
    UnexpectedAuthenticatedPrincipal,
    Stopped,
    Task,
}

impl fmt::Display for ProfilePublicationServiceError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Pool(error) => write!(formatter, "profile relay pool failed: {error}"),
            Self::InvalidConfig => {
                formatter.write_str("profile publisher configuration is invalid")
            }
            Self::PolicyMismatch => formatter
                .write_str("profile publisher relay policy does not match the pending intent"),
            Self::NoAuthenticatedRelay => {
                formatter.write_str("no pending profile relay authenticated before the deadline")
            }
            Self::AuthenticationRejected(message) => {
                write!(
                    formatter,
                    "profile relay authentication was rejected: {message}"
                )
            }
            Self::UnexpectedAuthenticatedPrincipal => {
                formatter.write_str("profile relay authenticated an unexpected principal")
            }
            Self::Stopped => formatter.write_str("profile publisher is stopped"),
            Self::Task => formatter.write_str("profile publisher task failed"),
        }
    }
}

impl Error for ProfilePublicationServiceError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Pool(error) => Some(error),
            _ => None,
        }
    }
}
