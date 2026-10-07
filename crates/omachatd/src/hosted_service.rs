//! Hosted server transport (ADR 0007).
//!
//! One task owns one WebSocket to the configured server: it connects,
//! verifies the server's hello signature against the pinned key, signs the
//! challenge with the daemon's device key, multiplexes requests, forwards
//! events, and reconnects with bounded backoff. The device secret never
//! enters this module: the core supplies a signing closure that refuses once
//! the identity has been erased, which stops the transport.
//!
//! Requests are answered in order by the server, but replies are matched by
//! identifier anyway so a lost frame cannot misattribute a result. A request
//! in flight when the connection drops fails with [`HostedError::Disconnected`]
//! and it is the caller's decision whether to repeat it; sends are safe to
//! repeat because the server deduplicates by client identifier.

use ed25519_dalek::{Signature, VerifyingKey};
use futures_util::{SinkExt, StreamExt};
use omachat_proto::hosted::{
    KEY_BYTES, MAX_FRAME_BYTES, PROTOCOL_VERSION, SIGNATURE_BYTES, ServerError, auth_transcript,
    hello_transcript,
};
use serde_json::{Value, json};
use std::{collections::HashMap, error::Error, fmt, sync::Arc, time::Duration};
use tokio::{
    net::TcpStream,
    sync::{mpsc, oneshot, watch},
    task::JoinHandle,
    time::{Instant, interval, sleep_until, timeout, timeout_at},
};
use tokio_tungstenite::{
    MaybeTlsStream, WebSocketStream, connect_async_with_config,
    tungstenite::{Message, protocol::WebSocketConfig},
};

/// IPC conversation identifiers for hosted conversations carry this prefix
/// followed by the server's conversation identifier.
pub const HOSTED_CONVERSATION_PREFIX: &str = "hosted:";
const MAX_CONVERSATION_ID_BYTES: usize = 128;
const REQUEST_QUEUE: usize = 64;
/// A session that lasted at least this long resets the reconnect backoff.
const STABLE_SESSION: Duration = Duration::from_secs(30);

type Socket = WebSocketStream<MaybeTlsStream<TcpStream>>;

#[must_use]
pub fn hosted_conversation_id(conversation_id: &str) -> String {
    format!("{HOSTED_CONVERSATION_PREFIX}{conversation_id}")
}

/// Strip the hosted prefix and validate the remaining server identifier.
#[must_use]
pub fn parse_hosted_conversation(conversation: &str) -> Option<&str> {
    let id = conversation.strip_prefix(HOSTED_CONVERSATION_PREFIX)?;
    if id.is_empty()
        || id.len() > MAX_CONVERSATION_ID_BYTES
        || !id
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-' || byte == b'_')
    {
        return None;
    }
    Some(id)
}

#[derive(Clone, Copy, Debug)]
pub struct HostedTimeouts {
    /// Whole handshake: TCP, TLS, WebSocket upgrade, hello and authenticate.
    pub connect: Duration,
    /// One request after authentication.
    pub request: Duration,
    /// How long a send keeps retrying across reconnects before it gives up.
    pub send: Duration,
    pub initial_backoff: Duration,
    pub max_backoff: Duration,
    pub keepalive: Duration,
}

impl Default for HostedTimeouts {
    fn default() -> Self {
        Self {
            connect: Duration::from_secs(20),
            request: Duration::from_secs(20),
            send: Duration::from_secs(25),
            initial_backoff: Duration::from_secs(1),
            max_backoff: Duration::from_secs(30),
            keepalive: Duration::from_secs(60),
        }
    }
}

/// Signs the authentication transcript with the device key, or returns
/// `None` once the identity is gone, which stops the transport.
pub type DeviceSigner = Arc<dyn Fn(&[u8]) -> Option<[u8; SIGNATURE_BYTES]> + Send + Sync>;

#[derive(Clone, Debug)]
pub struct HostedServiceConfig {
    pub url: String,
    pub pinned_server_public_key: [u8; KEY_BYTES],
    pub device_public_key: [u8; KEY_BYTES],
    pub display_name: Option<String>,
    pub invite_code: Option<String>,
    pub timeouts: HostedTimeouts,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct HostedAccount {
    pub account_id: String,
    pub handle: Option<String>,
    pub display_name: Option<String>,
    pub new_account: bool,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum HostedState {
    Connecting,
    Connected(HostedAccount),
    Disconnected { reason: String },
    Stopped,
}

impl HostedState {
    #[must_use]
    pub const fn label(&self) -> &'static str {
        match self {
            Self::Connecting => "connecting",
            Self::Connected(_) => "connected",
            Self::Disconnected { .. } => "disconnected",
            Self::Stopped => "stopped",
        }
    }

    #[must_use]
    pub const fn account(&self) -> Option<&HostedAccount> {
        match self {
            Self::Connected(account) => Some(account),
            _ => None,
        }
    }
}

#[derive(Clone, Debug)]
pub enum HostedEvent {
    State(HostedState),
    /// An unsolicited server event: `message`, `receipt`, `conversation`
    /// or `lagged`, with its `data` object.
    Server {
        kind: String,
        data: Value,
    },
}

#[derive(Debug)]
pub enum HostedError {
    /// The connection dropped before the reply arrived; the outcome of the
    /// request is unknown.
    Disconnected,
    Timeout,
    /// The transport has stopped for good (shutdown or erased identity).
    Stopped,
    /// The server refused the request.
    Server(ServerError),
    /// The server violated the protocol or failed the pin check.
    Protocol(String),
}

impl fmt::Display for HostedError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Disconnected => formatter.write_str("hosted server connection dropped"),
            Self::Timeout => formatter.write_str("hosted server did not answer in time"),
            Self::Stopped => formatter.write_str("hosted transport is stopped"),
            Self::Server(error) => write!(formatter, "hosted server refused: {}", error.message),
            Self::Protocol(reason) => write!(formatter, "hosted server protocol failure: {reason}"),
        }
    }
}

impl Error for HostedError {}

struct HostedRequest {
    method: &'static str,
    params: Value,
    reply: oneshot::Sender<Result<Value, HostedError>>,
}

#[derive(Clone)]
pub struct HostedHandle {
    requests: mpsc::Sender<HostedRequest>,
    state: watch::Receiver<HostedState>,
    timeouts: HostedTimeouts,
}

impl HostedHandle {
    #[must_use]
    pub fn state(&self) -> HostedState {
        self.state.borrow().clone()
    }

    #[must_use]
    pub const fn timeouts(&self) -> HostedTimeouts {
        self.timeouts
    }

    /// Send one request and wait for its reply or the request timeout.
    pub async fn call(&self, method: &'static str, params: Value) -> Result<Value, HostedError> {
        let (reply, receiver) = oneshot::channel();
        self.requests
            .send(HostedRequest {
                method,
                params,
                reply,
            })
            .await
            .map_err(|_| HostedError::Stopped)?;
        match timeout(self.timeouts.request, receiver).await {
            Ok(Ok(outcome)) => outcome,
            Ok(Err(_)) => Err(HostedError::Disconnected),
            Err(_) => Err(HostedError::Timeout),
        }
    }

    /// Wait until the transport is connected. `Disconnected` means the
    /// deadline passed first.
    pub async fn wait_connected(&self, deadline: Instant) -> Result<(), HostedError> {
        let mut state = self.state.clone();
        loop {
            match &*state.borrow() {
                HostedState::Connected(_) => return Ok(()),
                HostedState::Stopped => return Err(HostedError::Stopped),
                HostedState::Connecting | HostedState::Disconnected { .. } => {}
            }
            match timeout_at(deadline, state.changed()).await {
                Ok(Ok(())) => {}
                Ok(Err(_)) => return Err(HostedError::Stopped),
                Err(_) => return Err(HostedError::Disconnected),
            }
        }
    }
}

pub struct HostedService {
    handle: HostedHandle,
    stop: watch::Sender<bool>,
    task: JoinHandle<()>,
}

impl HostedService {
    /// Start the transport. Must be called inside a Tokio runtime.
    pub fn spawn(
        config: HostedServiceConfig,
        signer: DeviceSigner,
        events: mpsc::Sender<HostedEvent>,
    ) -> Result<Self, HostedServiceError> {
        let url = url::Url::parse(&config.url).map_err(|_| HostedServiceError::InvalidUrl)?;
        let loopback = url.scheme() == "ws"
            && matches!(
                url.host(),
                Some(url::Host::Ipv4(address)) if address.is_loopback()
            )
            || url.scheme() == "ws"
                && matches!(
                    url.host(),
                    Some(url::Host::Ipv6(address)) if address.is_loopback()
                );
        if url.scheme() != "wss" && !loopback {
            return Err(HostedServiceError::InvalidUrl);
        }
        let (request_sender, request_receiver) = mpsc::channel(REQUEST_QUEUE);
        let (state_sender, state_receiver) = watch::channel(HostedState::Connecting);
        let (stop_sender, stop_receiver) = watch::channel(false);
        let timeouts = config.timeouts;
        let task = tokio::spawn(run(
            config,
            signer,
            events,
            request_receiver,
            state_sender,
            stop_receiver,
        ));
        Ok(Self {
            handle: HostedHandle {
                requests: request_sender,
                state: state_receiver,
                timeouts,
            },
            stop: stop_sender,
            task,
        })
    }

    #[must_use]
    pub fn handle(&self) -> HostedHandle {
        self.handle.clone()
    }

    pub async fn shutdown(self) {
        let _ = self.stop.send(true);
        let _ = self.task.await;
    }
}

#[derive(Debug)]
pub enum HostedServiceError {
    InvalidUrl,
}

impl fmt::Display for HostedServiceError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidUrl => {
                formatter.write_str("hosted server URL must be wss:// or a loopback ws://")
            }
        }
    }
}

impl Error for HostedServiceError {}

async fn wait_stop(stop: &mut watch::Receiver<bool>) {
    loop {
        if *stop.borrow() {
            return;
        }
        if stop.changed().await.is_err() {
            return;
        }
    }
}

async fn publish_state(
    state: &watch::Sender<HostedState>,
    events: &mpsc::Sender<HostedEvent>,
    value: HostedState,
) {
    state.send_replace(value.clone());
    let _ = events.send(HostedEvent::State(value)).await;
}

async fn run(
    config: HostedServiceConfig,
    signer: DeviceSigner,
    events: mpsc::Sender<HostedEvent>,
    mut requests: mpsc::Receiver<HostedRequest>,
    state: watch::Sender<HostedState>,
    mut stop: watch::Receiver<bool>,
) {
    let mut backoff = config.timeouts.initial_backoff;
    'transport: loop {
        if *stop.borrow() {
            break;
        }
        publish_state(&state, &events, HostedState::Connecting).await;
        let started = Instant::now();
        let connected = tokio::select! {
            biased;
            () = wait_stop(&mut stop) => break,
            connected = connect(&config, &signer) => connected,
        };
        match connected {
            Ok((socket, account)) => {
                publish_state(&state, &events, HostedState::Connected(account)).await;
                let reason = session(socket, &config, &mut requests, &events, &mut stop).await;
                if *stop.borrow() {
                    break;
                }
                publish_state(&state, &events, HostedState::Disconnected { reason }).await;
                if started.elapsed() >= STABLE_SESSION {
                    backoff = config.timeouts.initial_backoff;
                }
            }
            Err(HostedError::Stopped) => break,
            Err(error) => {
                publish_state(
                    &state,
                    &events,
                    HostedState::Disconnected {
                        reason: error.to_string(),
                    },
                )
                .await;
            }
        }
        let wake = Instant::now() + backoff;
        backoff = (backoff * 2).min(config.timeouts.max_backoff);
        loop {
            tokio::select! {
                biased;
                () = wait_stop(&mut stop) => break 'transport,
                () = sleep_until(wake) => break,
                request = requests.recv() => match request {
                    Some(request) => {
                        let _ = request.reply.send(Err(HostedError::Disconnected));
                    }
                    None => break 'transport,
                },
            }
        }
    }
    publish_state(&state, &events, HostedState::Stopped).await;
    requests.close();
    while let Some(request) = requests.recv().await {
        let _ = request.reply.send(Err(HostedError::Stopped));
    }
}

async fn connect(
    config: &HostedServiceConfig,
    signer: &DeviceSigner,
) -> Result<(Socket, HostedAccount), HostedError> {
    timeout(config.timeouts.connect, handshake(config, signer))
        .await
        .map_err(|_| HostedError::Timeout)?
}

async fn handshake(
    config: &HostedServiceConfig,
    signer: &DeviceSigner,
) -> Result<(Socket, HostedAccount), HostedError> {
    let mut socket_config = WebSocketConfig::default();
    socket_config.max_message_size = Some(MAX_FRAME_BYTES);
    socket_config.max_frame_size = Some(MAX_FRAME_BYTES);
    let (mut socket, _) = connect_async_with_config(&config.url, Some(socket_config), false)
        .await
        .map_err(|error| HostedError::Protocol(format!("connect failed: {error}")))?;
    send_frame(
        &mut socket,
        json!({
            "version": PROTOCOL_VERSION,
            "id": "hello",
            "method": "hello",
            "params": {
                "minimum_version": PROTOCOL_VERSION,
                "maximum_version": PROTOCOL_VERSION,
                "device_public_key": hex::encode(config.device_public_key),
            },
        }),
    )
    .await?;
    let hello = expect_response(&mut socket, "hello").await?;
    let challenge = decode_fixed::<KEY_BYTES>(&hello, "challenge")?;
    let server_public_key = decode_fixed::<KEY_BYTES>(&hello, "server_public_key")?;
    if server_public_key != config.pinned_server_public_key {
        return Err(HostedError::Protocol(
            "server public key does not match the pinned key".into(),
        ));
    }
    let server_signature = decode_fixed::<SIGNATURE_BYTES>(&hello, "server_signature")?;
    VerifyingKey::from_bytes(&server_public_key)
        .map_err(|_| HostedError::Protocol("pinned key is not a valid Ed25519 key".into()))?
        .verify_strict(
            &hello_transcript(&challenge, &config.device_public_key),
            &Signature::from_bytes(&server_signature),
        )
        .map_err(|_| HostedError::Protocol("server hello signature did not verify".into()))?;
    let transcript = auth_transcript(&server_public_key, &challenge, &config.device_public_key);
    let device_signature = signer(&transcript).ok_or(HostedError::Stopped)?;
    send_frame(
        &mut socket,
        json!({
            "version": PROTOCOL_VERSION,
            "id": "authenticate",
            "method": "authenticate",
            "params": {
                "signature": hex::encode(device_signature),
                "display_name": config.display_name,
                "invite_code": config.invite_code,
            },
        }),
    )
    .await?;
    let registered = expect_response(&mut socket, "authenticate").await?;
    let account_id = registered
        .get("account_id")
        .and_then(Value::as_str)
        .ok_or_else(|| HostedError::Protocol("authenticate reply lacks account_id".into()))?
        .to_owned();
    let account = HostedAccount {
        account_id,
        handle: registered
            .get("handle")
            .and_then(Value::as_str)
            .map(str::to_owned),
        display_name: registered
            .get("display_name")
            .and_then(Value::as_str)
            .map(str::to_owned),
        new_account: registered
            .get("new_account")
            .and_then(Value::as_bool)
            .unwrap_or(false),
    };
    Ok((socket, account))
}

fn decode_fixed<const N: usize>(value: &Value, field: &str) -> Result<[u8; N], HostedError> {
    let encoded = value
        .get(field)
        .and_then(Value::as_str)
        .ok_or_else(|| HostedError::Protocol(format!("hello reply lacks {field}")))?;
    let bytes = hex::decode(encoded)
        .map_err(|_| HostedError::Protocol(format!("hello reply field {field} is not hex")))?;
    bytes.try_into().map_err(|_| {
        HostedError::Protocol(format!("hello reply field {field} has the wrong length"))
    })
}

async fn send_frame(socket: &mut Socket, frame: Value) -> Result<(), HostedError> {
    socket
        .send(Message::Text(frame.to_string().into()))
        .await
        .map_err(|_| HostedError::Disconnected)
}

/// Read frames until the response with `id` arrives. Events cannot arrive
/// before authentication, so anything else is a protocol violation.
async fn expect_response(socket: &mut Socket, id: &str) -> Result<Value, HostedError> {
    loop {
        match socket.next().await {
            None | Some(Ok(Message::Close(_))) => return Err(HostedError::Disconnected),
            Some(Err(_)) => return Err(HostedError::Disconnected),
            Some(Ok(Message::Text(text))) => {
                let value: Value = serde_json::from_str(text.as_str())
                    .map_err(|_| HostedError::Protocol("server sent malformed JSON".into()))?;
                if value.get("id").and_then(Value::as_str) == Some(id) {
                    return response_outcome(value);
                }
                return Err(HostedError::Protocol(
                    "server answered out of order during the handshake".into(),
                ));
            }
            Some(Ok(Message::Ping(payload))) => {
                socket
                    .send(Message::Pong(payload))
                    .await
                    .map_err(|_| HostedError::Disconnected)?;
            }
            Some(Ok(Message::Pong(_))) => {}
            Some(Ok(_)) => {
                return Err(HostedError::Protocol("server sent a binary frame".into()));
            }
        }
    }
}

fn response_outcome(mut value: Value) -> Result<Value, HostedError> {
    match value.get("ok").and_then(Value::as_bool) {
        Some(true) => Ok(value
            .get_mut("result")
            .map(Value::take)
            .unwrap_or(Value::Null)),
        Some(false) => {
            let error = value
                .get_mut("error")
                .map(Value::take)
                .unwrap_or(Value::Null);
            serde_json::from_value::<ServerError>(error)
                .map(|error| Err(HostedError::Server(error)))
                .map_err(|_| HostedError::Protocol("server sent a malformed error".into()))?
        }
        None => Err(HostedError::Protocol(
            "server response lacks an ok field".into(),
        )),
    }
}

/// Serve one authenticated connection until it ends. Returns the reason.
async fn session(
    mut socket: Socket,
    config: &HostedServiceConfig,
    requests: &mut mpsc::Receiver<HostedRequest>,
    events: &mpsc::Sender<HostedEvent>,
    stop: &mut watch::Receiver<bool>,
) -> String {
    let mut pending: HashMap<String, oneshot::Sender<Result<Value, HostedError>>> = HashMap::new();
    let mut next_id: u64 = 1;
    let mut keepalive = interval(config.timeouts.keepalive);
    keepalive.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    keepalive.tick().await;
    let reason = loop {
        tokio::select! {
            biased;
            () = wait_stop(stop) => {
                let _ = socket.close(None).await;
                break "stopped".to_owned();
            }
            request = requests.recv() => {
                let Some(request) = request else {
                    break "daemon closed the transport".to_owned();
                };
                let id = next_id.to_string();
                next_id += 1;
                let mut frame = json!({
                    "version": PROTOCOL_VERSION,
                    "id": id,
                    "method": request.method,
                });
                if !request.params.is_null() {
                    frame["params"] = request.params;
                }
                if socket.send(Message::Text(frame.to_string().into())).await.is_err() {
                    let _ = request.reply.send(Err(HostedError::Disconnected));
                    break "send failed".to_owned();
                }
                pending.insert(id, request.reply);
            }
            frame = socket.next() => match frame {
                None | Some(Ok(Message::Close(_))) => break "server closed the connection".to_owned(),
                Some(Err(error)) => break format!("connection failed: {error}"),
                Some(Ok(Message::Text(text))) => {
                    let Ok(value) = serde_json::from_str::<Value>(text.as_str()) else {
                        break "server sent malformed JSON".to_owned();
                    };
                    if let Some(kind) = value.get("event").and_then(Value::as_str) {
                        let data = value.get("data").cloned().unwrap_or(Value::Null);
                        if events
                            .send(HostedEvent::Server { kind: kind.to_owned(), data })
                            .await
                            .is_err()
                        {
                            break "daemon stopped consuming events".to_owned();
                        }
                    } else if let Some(id) = value.get("id").and_then(Value::as_str) {
                        if let Some(reply) = pending.remove(id) {
                            let _ = reply.send(response_outcome(value));
                        }
                    } else {
                        break "server sent an uncorrelated frame".to_owned();
                    }
                }
                Some(Ok(Message::Ping(payload))) => {
                    if socket.send(Message::Pong(payload)).await.is_err() {
                        break "pong failed".to_owned();
                    }
                }
                Some(Ok(Message::Pong(_))) => {}
                Some(Ok(_)) => break "server sent a binary frame".to_owned(),
            },
            _ = keepalive.tick() => {
                if socket.send(Message::Ping(Vec::new().into())).await.is_err() {
                    break "keepalive failed".to_owned();
                }
            }
        }
    };
    // Dropping the pending senders answers every in-flight request with
    // `Disconnected`, which is exactly the truth: their outcome is unknown.
    drop(pending);
    reason
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hosted_conversation_ids_round_trip_and_reject_hostile_values() {
        assert_eq!(hosted_conversation_id("ab12"), "hosted:ab12");
        assert_eq!(parse_hosted_conversation("hosted:ab12"), Some("ab12"));
        assert_eq!(parse_hosted_conversation("hosted:"), None);
        assert_eq!(parse_hosted_conversation("hosted:a/b"), None);
        assert_eq!(parse_hosted_conversation("dm:ab12"), None);
        assert_eq!(
            parse_hosted_conversation(&format!("hosted:{}", "a".repeat(129))),
            None
        );
    }

    #[test]
    fn response_outcomes_distinguish_results_errors_and_garbage() {
        assert_eq!(
            response_outcome(json!({"ok": true, "result": {"x": 1}})).unwrap(),
            json!({"x": 1})
        );
        assert!(matches!(
            response_outcome(json!({"ok": false, "error": {"code": "not-found", "message": "gone"}})),
            Err(HostedError::Server(error)) if error.code == omachat_proto::hosted::ErrorCode::NotFound
        ));
        assert!(matches!(
            response_outcome(json!({"ok": false, "error": "nope"})),
            Err(HostedError::Protocol(_))
        ));
        assert!(matches!(
            response_outcome(json!({"result": 1})),
            Err(HostedError::Protocol(_))
        ));
    }

    #[tokio::test]
    async fn spawn_rejects_insecure_urls() {
        let (events, _receiver) = mpsc::channel(1);
        let signer: DeviceSigner = Arc::new(|_| None);
        let config = HostedServiceConfig {
            url: "ws://chat.example/ws".into(),
            pinned_server_public_key: [1_u8; KEY_BYTES],
            device_public_key: [2_u8; KEY_BYTES],
            display_name: None,
            invite_code: None,
            timeouts: HostedTimeouts::default(),
        };
        assert!(matches!(
            HostedService::spawn(config, signer, events),
            Err(HostedServiceError::InvalidUrl)
        ));
    }
}
