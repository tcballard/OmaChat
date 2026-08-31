//! Bounded, cancellation-safe connection to one Nostr relay.

use crate::{
    event::{EventLimits, SignedEvent},
    frame::{ClientFrame, FrameError, FrameLimits, RelayFrame},
};
use futures_util::{SinkExt, StreamExt};
use serde_json::Value;
use std::{
    collections::HashMap,
    error::Error,
    fmt,
    hash::{DefaultHasher, Hash, Hasher},
    time::{Duration, SystemTime, UNIX_EPOCH},
};
use tokio::{
    io::{AsyncRead, AsyncWrite},
    net::TcpStream,
    sync::{mpsc, oneshot, watch},
    task::JoinHandle,
};
use tokio_socks::tcp::Socks5Stream;
use tokio_tungstenite::{
    MaybeTlsStream, WebSocketStream, client_async_tls_with_config,
    tungstenite::{Error as WebSocketError, Message},
};
use url::Url;

trait RelayIo: AsyncRead + AsyncWrite + Send + Unpin {}
impl<T: AsyncRead + AsyncWrite + Send + Unpin> RelayIo for T {}
type BoxedIo = Box<dyn RelayIo>;
type RelaySocket = WebSocketStream<MaybeTlsStream<BoxedIo>>;

/// How the relay hostname is reached. SOCKS always receives the unresolved
/// hostname so the proxy, rather than the local resolver, owns DNS.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum RelayRoute {
    Direct,
    Socks5(String),
}

/// Explicit limits and timers for one relay actor.
#[derive(Clone, Debug)]
pub struct RelayConfig {
    pub url: String,
    pub route: RelayRoute,
    pub command_capacity: usize,
    pub notification_capacity: usize,
    pub connect_timeout: Duration,
    pub ping_interval: Duration,
    pub idle_timeout: Duration,
    pub response_timeout: Duration,
    pub reconnect_initial_delay: Duration,
    pub reconnect_max_delay: Duration,
    pub event_limits: EventLimits,
    pub frame_limits: FrameLimits,
}

impl RelayConfig {
    /// Construct production defaults for a relay URL and route.
    #[must_use]
    pub fn new(url: String, route: RelayRoute) -> Self {
        Self {
            url,
            route,
            command_capacity: 64,
            notification_capacity: 256,
            connect_timeout: Duration::from_secs(20),
            ping_interval: Duration::from_secs(30),
            idle_timeout: Duration::from_secs(90),
            response_timeout: Duration::from_secs(20),
            reconnect_initial_delay: Duration::from_secs(1),
            reconnect_max_delay: Duration::from_secs(60),
            event_limits: EventLimits::default(),
            frame_limits: FrameLimits::default(),
        }
    }

    fn validate(&self) -> Result<(), RelayError> {
        if self.command_capacity == 0 || self.notification_capacity == 0 {
            return Err(RelayError::InvalidConfig(
                "queue capacities must be non-zero",
            ));
        }
        if self.connect_timeout.is_zero()
            || self.ping_interval.is_zero()
            || self.idle_timeout <= self.ping_interval
            || self.response_timeout.is_zero()
            || self.reconnect_initial_delay.is_zero()
            || self.reconnect_max_delay < self.reconnect_initial_delay
        {
            return Err(RelayError::InvalidConfig("invalid relay timer ordering"));
        }
        let parsed = Url::parse(&self.url).map_err(RelayError::Url)?;
        if !matches!(parsed.scheme(), "ws" | "wss")
            || parsed.host_str().is_none()
            || parsed.port_or_known_default().is_none()
        {
            return Err(RelayError::InvalidConfig(
                "relay URL must be ws:// or wss://",
            ));
        }
        Ok(())
    }
}

/// Current actor health, observable without consuming notifications.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RelayHealth {
    Connecting,
    Connected,
    Disconnected,
    Stopped,
}

/// Authenticated relay input and lifecycle changes.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum RelayNotification {
    Connected,
    Disconnected,
    Event {
        subscription_id: String,
        event: SignedEvent,
    },
    EndOfStoredEvents {
        subscription_id: String,
    },
    Closed {
        subscription_id: String,
        message: String,
    },
    Notice(String),
    AuthChallenge(String),
}

/// Successful acknowledgement returned by a relay for a published event.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PublishAcknowledgement {
    pub event_id: String,
    pub message: String,
}

/// Handle for one reconnecting relay actor.
pub struct RelayConnection {
    commands: mpsc::Sender<Command>,
    notifications: mpsc::Receiver<RelayNotification>,
    health: watch::Receiver<RelayHealth>,
    response_timeout: Duration,
    task: Option<JoinHandle<Result<(), RelayError>>>,
}

impl RelayConnection {
    /// Start one bounded actor. Network activity begins on the spawned task.
    pub fn spawn(config: RelayConfig) -> Result<Self, RelayError> {
        config.validate()?;
        let (command_sender, command_receiver) = mpsc::channel(config.command_capacity);
        let (notification_sender, notification_receiver) =
            mpsc::channel(config.notification_capacity);
        let (health_sender, health_receiver) = watch::channel(RelayHealth::Connecting);
        let response_timeout = config.response_timeout;
        let task = tokio::spawn(run_actor(
            config,
            command_receiver,
            notification_sender,
            health_sender,
        ));
        Ok(Self {
            commands: command_sender,
            notifications: notification_receiver,
            health: health_receiver,
            response_timeout,
            task: Some(task),
        })
    }

    /// Publish a signed event and wait for its matching `OK` response.
    pub async fn publish(&self, event: SignedEvent) -> Result<PublishAcknowledgement, RelayError> {
        let (sender, receiver) = oneshot::channel();
        self.send(Command::Publish {
            event,
            response: sender,
        })
        .await?;
        tokio::time::timeout(self.response_timeout, receiver)
            .await
            .map_err(|_| RelayError::ResponseTimeout)?
            .map_err(|_| RelayError::Stopped)?
    }

    /// Create or replace a subscription. Active subscriptions are replayed
    /// after reconnect before new commands are processed.
    pub async fn subscribe(
        &self,
        subscription_id: String,
        filters: Vec<Value>,
    ) -> Result<(), RelayError> {
        let (sender, receiver) = oneshot::channel();
        self.send(Command::Subscribe {
            subscription_id,
            filters,
            response: sender,
        })
        .await?;
        tokio::time::timeout(self.response_timeout, receiver)
            .await
            .map_err(|_| RelayError::ResponseTimeout)?
            .map_err(|_| RelayError::Stopped)?
    }

    /// Close a subscription and prevent it from replaying after reconnect.
    pub async fn close_subscription(&self, subscription_id: String) -> Result<(), RelayError> {
        let (sender, receiver) = oneshot::channel();
        self.send(Command::Close {
            subscription_id,
            response: sender,
        })
        .await?;
        tokio::time::timeout(self.response_timeout, receiver)
            .await
            .map_err(|_| RelayError::ResponseTimeout)?
            .map_err(|_| RelayError::Stopped)?
    }

    /// Receive the next bounded notification.
    pub async fn next_notification(&mut self) -> Option<RelayNotification> {
        self.notifications.recv().await
    }

    /// Borrow the actor's current health receiver.
    #[must_use]
    pub fn health(&self) -> watch::Receiver<RelayHealth> {
        self.health.clone()
    }

    /// Stop the actor, close its socket, and await owned work.
    pub async fn shutdown(mut self) -> Result<(), RelayError> {
        let (sender, receiver) = oneshot::channel();
        if self.commands.send(Command::Shutdown(sender)).await.is_ok() {
            let _ = tokio::time::timeout(self.response_timeout, receiver).await;
        }
        match self.task.take() {
            Some(task) => task.await.map_err(|_| RelayError::Task)?,
            None => Ok(()),
        }
    }

    async fn send(&self, command: Command) -> Result<(), RelayError> {
        self.commands
            .try_send(command)
            .map_err(|error| match error {
                mpsc::error::TrySendError::Full(_) => RelayError::Backpressure,
                mpsc::error::TrySendError::Closed(_) => RelayError::Stopped,
            })
    }
}

enum Command {
    Publish {
        event: SignedEvent,
        response: oneshot::Sender<Result<PublishAcknowledgement, RelayError>>,
    },
    Subscribe {
        subscription_id: String,
        filters: Vec<Value>,
        response: oneshot::Sender<Result<(), RelayError>>,
    },
    Close {
        subscription_id: String,
        response: oneshot::Sender<Result<(), RelayError>>,
    },
    Shutdown(oneshot::Sender<()>),
}

async fn run_actor(
    config: RelayConfig,
    commands: mpsc::Receiver<Command>,
    notifications: mpsc::Sender<RelayNotification>,
    health: watch::Sender<RelayHealth>,
) -> Result<(), RelayError> {
    let terminal_health = health.clone();
    let result = run_actor_loop(config, commands, notifications, health).await;
    let _ = terminal_health.send(RelayHealth::Stopped);
    result
}

async fn run_actor_loop(
    config: RelayConfig,
    mut commands: mpsc::Receiver<Command>,
    notifications: mpsc::Sender<RelayNotification>,
    health: watch::Sender<RelayHealth>,
) -> Result<(), RelayError> {
    let mut subscriptions: HashMap<String, Vec<Value>> = HashMap::new();
    let mut pending: HashMap<String, oneshot::Sender<Result<PublishAcknowledgement, RelayError>>> =
        HashMap::new();
    let mut consecutive_failures = 0_u32;
    loop {
        let _ = health.send(RelayHealth::Connecting);
        let mut socket = match connect(&config).await {
            Ok(socket) => socket,
            Err(_) => {
                let _ = health.send(RelayHealth::Disconnected);
                consecutive_failures = consecutive_failures.saturating_add(1);
                if wait_to_reconnect(
                    &mut commands,
                    reconnect_delay(&config, consecutive_failures),
                )
                .await?
                {
                    break;
                }
                continue;
            }
        };
        let _ = health.send(RelayHealth::Connected);
        notify(&notifications, RelayNotification::Connected)?;
        for (subscription_id, filters) in &subscriptions {
            send_frame(
                &mut socket,
                &ClientFrame::Request {
                    subscription_id: subscription_id.clone(),
                    filters: filters.clone(),
                },
                &config.frame_limits,
            )
            .await?;
        }

        let mut ping = tokio::time::interval(config.ping_interval);
        ping.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        let idle = tokio::time::sleep(config.idle_timeout);
        tokio::pin!(idle);
        let mut session_progress = false;
        let disconnect = loop {
            tokio::select! {
                command = commands.recv() => {
                    match command {
                        Some(Command::Publish { event, response }) => {
                            let id = event.id.clone();
                            if pending.get(&id).is_some_and(|sender| !sender.is_closed()) {
                                let _ = response.send(Err(RelayError::DuplicatePublish));
                                continue;
                            }
                            pending.remove(&id);
                            match send_frame(&mut socket, &ClientFrame::Event(event), &config.frame_limits).await {
                                Ok(()) => { pending.insert(id, response); }
                                Err(error) => {
                                    let _ = response.send(Err(error));
                                    break true;
                                }
                            }
                        }
                        Some(Command::Subscribe { subscription_id, filters, response }) => {
                            let frame = ClientFrame::Request { subscription_id: subscription_id.clone(), filters: filters.clone() };
                            match send_frame(&mut socket, &frame, &config.frame_limits).await {
                                Ok(()) => {
                                    subscriptions.insert(subscription_id, filters);
                                    let _ = response.send(Ok(()));
                                }
                                Err(error) => {
                                    let _ = response.send(Err(error));
                                    break true;
                                }
                            }
                        }
                        Some(Command::Close { subscription_id, response }) => {
                            subscriptions.remove(&subscription_id);
                            match send_frame(&mut socket, &ClientFrame::Close { subscription_id }, &config.frame_limits).await {
                                Ok(()) => { let _ = response.send(Ok(())); }
                                Err(error) => {
                                    let _ = response.send(Err(error));
                                    break true;
                                }
                            }
                        }
                        Some(Command::Shutdown(response)) => {
                            let _ = socket.close(None).await;
                            let _ = response.send(());
                            break false;
                        }
                        None => break false,
                    }
                }
                message = socket.next() => {
                    let Some(message) = message else { break true; };
                    match message {
                        Ok(Message::Text(text)) => {
                            session_progress = true;
                            idle.as_mut().reset(tokio::time::Instant::now() + config.idle_timeout);
                            if handle_relay_frame(
                                text.as_bytes(),
                                &config,
                                &notifications,
                                &mut pending,
                            ).is_err() {
                                break true;
                            }
                        }
                        Ok(Message::Pong(_)) | Ok(Message::Ping(_)) => {
                            session_progress = true;
                            idle.as_mut().reset(tokio::time::Instant::now() + config.idle_timeout);
                        }
                        Ok(Message::Close(_)) | Err(_) => break true,
                        Ok(Message::Binary(_)) | Ok(Message::Frame(_)) => break true,
                    }
                }
                _ = ping.tick() => {
                    if socket.send(Message::Ping(Vec::new().into())).await.is_err() {
                        break true;
                    }
                }
                () = &mut idle => break true,
            }
        };
        if !disconnect {
            break;
        }
        fail_pending(&mut pending, RelayError::Disconnected);
        let _ = health.send(RelayHealth::Disconnected);
        notify(&notifications, RelayNotification::Disconnected)?;
        consecutive_failures = if session_progress {
            0
        } else {
            consecutive_failures.saturating_add(1)
        };
        if wait_to_reconnect(
            &mut commands,
            reconnect_delay(&config, consecutive_failures),
        )
        .await?
        {
            break;
        }
    }
    fail_pending(&mut pending, RelayError::Stopped);
    Ok(())
}

fn reconnect_delay(config: &RelayConfig, failures: u32) -> Duration {
    let exponent = failures.saturating_sub(1).min(20);
    let capped_millis = config
        .reconnect_initial_delay
        .as_millis()
        .saturating_mul(1_u128 << exponent)
        .min(config.reconnect_max_delay.as_millis());
    let mut hasher = DefaultHasher::new();
    config.url.hash(&mut hasher);
    failures.hash(&mut hasher);
    let jitter_per_mille = 750_u128 + u128::from(hasher.finish() % 501);
    let jittered = capped_millis
        .saturating_mul(jitter_per_mille)
        .saturating_div(1000)
        .max(1)
        .min(config.reconnect_max_delay.as_millis());
    Duration::from_millis(u64::try_from(jittered).unwrap_or(u64::MAX))
}

async fn wait_to_reconnect(
    commands: &mut mpsc::Receiver<Command>,
    delay: Duration,
) -> Result<bool, RelayError> {
    tokio::select! {
        () = tokio::time::sleep(delay) => Ok(false),
        command = commands.recv() => match command {
            Some(Command::Shutdown(response)) => {
                let _ = response.send(());
                Ok(true)
            }
            Some(other) => {
                reject_command(other, RelayError::Disconnected);
                Ok(false)
            }
            None => Ok(true),
        }
    }
}

fn reject_command(command: Command, error: RelayError) {
    match command {
        Command::Publish { response, .. } => {
            let _ = response.send(Err(error));
        }
        Command::Subscribe { response, .. } | Command::Close { response, .. } => {
            let _ = response.send(Err(error));
        }
        Command::Shutdown(response) => {
            let _ = response.send(());
        }
    }
}

fn handle_relay_frame(
    bytes: &[u8],
    config: &RelayConfig,
    notifications: &mpsc::Sender<RelayNotification>,
    pending: &mut HashMap<String, oneshot::Sender<Result<PublishAcknowledgement, RelayError>>>,
) -> Result<(), RelayError> {
    let frame = RelayFrame::from_json(
        bytes,
        unix_timestamp(),
        &config.event_limits,
        &config.frame_limits,
    )?;
    match frame {
        RelayFrame::Event {
            subscription_id,
            event,
        } => notify(
            notifications,
            RelayNotification::Event {
                subscription_id,
                event,
            },
        ),
        RelayFrame::EndOfStoredEvents { subscription_id } => notify(
            notifications,
            RelayNotification::EndOfStoredEvents { subscription_id },
        ),
        RelayFrame::Ok {
            event_id,
            accepted,
            message,
        } => {
            if let Some(response) = pending.remove(&event_id) {
                let result = if accepted {
                    Ok(PublishAcknowledgement { event_id, message })
                } else {
                    Err(RelayError::PublishRejected(message))
                };
                let _ = response.send(result);
            }
            Ok(())
        }
        RelayFrame::Closed {
            subscription_id,
            message,
        } => notify(
            notifications,
            RelayNotification::Closed {
                subscription_id,
                message,
            },
        ),
        RelayFrame::Notice(message) => notify(notifications, RelayNotification::Notice(message)),
        RelayFrame::AuthChallenge(challenge) => {
            notify(notifications, RelayNotification::AuthChallenge(challenge))
        }
    }
}

fn notify(
    sender: &mpsc::Sender<RelayNotification>,
    notification: RelayNotification,
) -> Result<(), RelayError> {
    sender.try_send(notification).map_err(|error| match error {
        mpsc::error::TrySendError::Full(_) => RelayError::Backpressure,
        mpsc::error::TrySendError::Closed(_) => RelayError::Stopped,
    })
}

fn fail_pending(
    pending: &mut HashMap<String, oneshot::Sender<Result<PublishAcknowledgement, RelayError>>>,
    error: RelayError,
) {
    for (_, response) in pending.drain() {
        let _ = response.send(Err(error.clone()));
    }
}

async fn send_frame(
    socket: &mut RelaySocket,
    frame: &ClientFrame,
    limits: &FrameLimits,
) -> Result<(), RelayError> {
    let bytes = frame.to_json(limits)?;
    let text = String::from_utf8(bytes).map_err(|_| RelayError::Utf8)?;
    socket.send(Message::Text(text.into())).await?;
    Ok(())
}

async fn connect(config: &RelayConfig) -> Result<RelaySocket, RelayError> {
    tokio::time::timeout(config.connect_timeout, connect_inner(config))
        .await
        .map_err(|_| RelayError::ConnectTimeout)?
}

async fn connect_inner(config: &RelayConfig) -> Result<RelaySocket, RelayError> {
    let parsed = Url::parse(&config.url).map_err(RelayError::Url)?;
    let host = parsed
        .host_str()
        .ok_or(RelayError::InvalidConfig("missing relay host"))?;
    let port = parsed
        .port_or_known_default()
        .ok_or(RelayError::InvalidConfig("missing relay port"))?;
    let stream: BoxedIo = match &config.route {
        RelayRoute::Direct => Box::new(TcpStream::connect((host, port)).await?),
        RelayRoute::Socks5(proxy) => {
            Box::new(Socks5Stream::connect(proxy.as_str(), (host, port)).await?)
        }
    };
    let (socket, _) = client_async_tls_with_config(&config.url, stream, None, None).await?;
    Ok(socket)
}

fn unix_timestamp() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

/// Relay actor failures. Clone is intentional so one disconnect reason can be
/// delivered to every in-flight publisher without retaining opaque errors.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum RelayError {
    InvalidConfig(&'static str),
    Url(url::ParseError),
    Io(String),
    WebSocket(String),
    Socks(String),
    Frame(String),
    Utf8,
    Backpressure,
    ConnectTimeout,
    ResponseTimeout,
    Disconnected,
    Stopped,
    Task,
    DuplicatePublish,
    PublishRejected(String),
}

impl fmt::Display for RelayError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidConfig(message) => write!(formatter, "invalid relay config: {message}"),
            Self::Url(error) => write!(formatter, "invalid relay URL: {error}"),
            Self::Io(error) => write!(formatter, "relay I/O failed: {error}"),
            Self::WebSocket(error) => write!(formatter, "relay WebSocket failed: {error}"),
            Self::Socks(error) => write!(formatter, "relay SOCKS5 failed: {error}"),
            Self::Frame(error) => write!(formatter, "invalid relay frame: {error}"),
            Self::Utf8 => formatter.write_str("relay frame encoder produced non-UTF-8 bytes"),
            Self::Backpressure => formatter.write_str("relay notification queue is full"),
            Self::ConnectTimeout => formatter.write_str("relay connection timed out"),
            Self::ResponseTimeout => formatter.write_str("relay response timed out"),
            Self::Disconnected => formatter.write_str("relay disconnected"),
            Self::Stopped => formatter.write_str("relay actor stopped"),
            Self::Task => formatter.write_str("relay task failed"),
            Self::DuplicatePublish => {
                formatter.write_str("event is already awaiting acknowledgement")
            }
            Self::PublishRejected(message) => write!(formatter, "relay rejected event: {message}"),
        }
    }
}

impl Error for RelayError {}

impl From<std::io::Error> for RelayError {
    fn from(error: std::io::Error) -> Self {
        Self::Io(error.to_string())
    }
}

impl From<WebSocketError> for RelayError {
    fn from(error: WebSocketError) -> Self {
        Self::WebSocket(error.to_string())
    }
}

impl From<tokio_socks::Error> for RelayError {
    fn from(error: tokio_socks::Error) -> Self {
        Self::Socks(error.to_string())
    }
}

impl From<FrameError> for RelayError {
    fn from(error: FrameError) -> Self {
        Self::Frame(error.to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reconnect_backoff_is_jittered_bounded_and_grows() {
        let mut config = RelayConfig::new("wss://relay.invalid/".into(), RelayRoute::Direct);
        config.reconnect_initial_delay = Duration::from_millis(100);
        config.reconnect_max_delay = Duration::from_secs(2);
        let first = reconnect_delay(&config, 1);
        let fourth = reconnect_delay(&config, 4);
        let capped = reconnect_delay(&config, 100);
        assert!((Duration::from_millis(75)..=Duration::from_millis(125)).contains(&first));
        assert!(fourth > first);
        assert!(capped <= config.reconnect_max_delay);
        assert_ne!(reconnect_delay(&config, 2), reconnect_delay(&config, 3));
    }
}
