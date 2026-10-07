//! One WebSocket connection: handshake, authentication, request loop and
//! event delivery.

use crate::{
    auth::{
        KEY_BYTES, ServerIdentity, decode_key, decode_signature, random_challenge,
        verify_device_signature,
    },
    protocol::{
        Command, EVENT_LAGGED, ErrorCode, MAX_FRAME_BYTES, MAX_REQUEST_ID_BYTES, PROTOCOL_VERSION,
        Request, ServerError, event_frame, failure_frame, success_frame,
    },
    service::{EVENT_QUEUE_FRAMES, ServiceHandle, ServiceRequest},
};
use futures_util::{SinkExt, StreamExt};
use serde_json::json;
use std::{
    error::Error,
    fmt,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};
use tokio::{
    io::{AsyncRead, AsyncWrite},
    sync::{mpsc, watch},
    time::{interval, timeout},
};
use tokio_tungstenite::{
    WebSocketStream, accept_async_with_config,
    tungstenite::{self, Message, protocol::WebSocketConfig},
};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SessionLimits {
    /// WebSocket handshake deadline.
    pub admission_timeout: Duration,
    /// Deadline for hello and authenticate after the handshake.
    pub unauthenticated_timeout: Duration,
    /// Close a connection that sent nothing for this long.
    pub idle_timeout: Duration,
    /// Sustained request rate per connection.
    pub requests_per_second: u32,
    /// Burst allowance per connection.
    pub request_burst: u32,
}

impl Default for SessionLimits {
    fn default() -> Self {
        Self {
            admission_timeout: Duration::from_secs(10),
            unauthenticated_timeout: Duration::from_secs(15),
            idle_timeout: Duration::from_secs(300),
            requests_per_second: 20,
            request_burst: 40,
        }
    }
}

pub struct SessionContext {
    pub service: ServiceHandle,
    pub identity: Arc<ServerIdentity>,
    pub limits: SessionLimits,
    pub session_id: u64,
    pub shutdown: watch::Receiver<bool>,
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub enum CloseReason {
    #[default]
    ClientClosed,
    ProtocolViolation,
    AuthenticationFailed,
    Idle,
    Lagged,
    Shutdown,
    /// The transport or the service failed; `SessionReport::error` says how.
    Failed,
}

/// What happened on one connection. A transport error after authentication
/// still counts the session as authenticated; `error` carries the cause.
#[derive(Debug, Default)]
pub struct SessionReport {
    pub authenticated: bool,
    pub requests: u64,
    pub reason: CloseReason,
    pub error: Option<SessionError>,
}

struct Authenticated {
    account_id: String,
    device_public_key: [u8; KEY_BYTES],
}

pub async fn run_session<S>(stream: S, context: SessionContext) -> SessionReport
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let mut report = SessionReport::default();
    if let Err(error) = run(stream, context, &mut report).await {
        report.reason = CloseReason::Failed;
        report.error = Some(error);
    }
    report
}

async fn run<S>(
    stream: S,
    mut context: SessionContext,
    report: &mut SessionReport,
) -> Result<(), SessionError>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let mut config = WebSocketConfig::default();
    config.max_message_size = Some(MAX_FRAME_BYTES);
    config.max_frame_size = Some(MAX_FRAME_BYTES);
    let mut socket = timeout(
        context.limits.admission_timeout,
        accept_async_with_config(stream, Some(config)),
    )
    .await
    .map_err(|_| SessionError::AdmissionTimeout)?
    .map_err(SessionError::WebSocket)?;

    let authenticated = match timeout(
        context.limits.unauthenticated_timeout,
        authenticate(&mut socket, &context, report),
    )
    .await
    {
        Ok(Ok(Some(authenticated))) => authenticated,
        Ok(Ok(None)) => {
            let _ = socket.close(None).await;
            return Ok(());
        }
        Ok(Err(error)) => return Err(error),
        Err(_) => {
            let _ = socket.close(None).await;
            return Err(SessionError::AuthenticationTimeout);
        }
    };
    report.authenticated = true;

    let (events, mut inbox) = mpsc::channel(EVENT_QUEUE_FRAMES);
    let lagged = Arc::new(AtomicBool::new(false));
    context
        .service
        .call(ServiceRequest::Attach {
            account_id: authenticated.account_id.clone(),
            session_id: context.session_id,
            events,
            lagged: Arc::clone(&lagged),
        })
        .await
        .map_err(SessionError::Service)?;

    let outcome = serve(
        &mut socket,
        &mut context,
        &authenticated,
        &mut inbox,
        &lagged,
        report,
    )
    .await;
    let _ = context
        .service
        .call(ServiceRequest::Detach {
            account_id: authenticated.account_id,
            session_id: context.session_id,
        })
        .await;
    let _ = socket.close(None).await;
    outcome
}

async fn serve<S>(
    socket: &mut WebSocketStream<S>,
    context: &mut SessionContext,
    authenticated: &Authenticated,
    inbox: &mut mpsc::Receiver<String>,
    lagged: &AtomicBool,
    report: &mut SessionReport,
) -> Result<(), SessionError>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let mut bucket = TokenBucket::new(
        context.limits.request_burst,
        context.limits.requests_per_second,
    );
    let mut last_activity = Instant::now();
    let mut idle_tick = interval(Duration::from_secs(1).min(context.limits.idle_timeout));
    idle_tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    loop {
        tokio::select! {
            biased;
            changed = context.shutdown.changed() => {
                if changed.is_err() || *context.shutdown.borrow() {
                    report.reason = CloseReason::Shutdown;
                    return Ok(());
                }
            }
            frame = inbox.recv() => {
                let Some(frame) = frame else {
                    report.reason = CloseReason::Shutdown;
                    return Ok(());
                };
                send_text(socket, frame).await?;
                if lagged.load(Ordering::SeqCst) {
                    send_text(socket, event_frame(EVENT_LAGGED, json!({
                        "message": "events were dropped; reload conversations and history",
                    }))).await?;
                    report.reason = CloseReason::Lagged;
                    return Ok(());
                }
            }
            message = socket.next() => {
                let Some(message) = message else {
                    report.reason = CloseReason::ClientClosed;
                    return Ok(());
                };
                last_activity = Instant::now();
                match message.map_err(SessionError::WebSocket)? {
                    Message::Text(text) => {
                        report.requests += 1;
                        if !handle_request(socket, context, authenticated, &mut bucket, text.as_str()).await? {
                            report.reason = CloseReason::ProtocolViolation;
                            return Ok(());
                        }
                    }
                    Message::Ping(payload) => {
                        socket.send(Message::Pong(payload)).await.map_err(SessionError::WebSocket)?;
                    }
                    Message::Pong(_) => {}
                    Message::Close(_) => {
                        report.reason = CloseReason::ClientClosed;
                        return Ok(());
                    }
                    Message::Binary(_) | Message::Frame(_) => {
                        send_text(socket, failure_frame("", &ServerError::new(
                            ErrorCode::InvalidRequest,
                            "only JSON text frames are accepted",
                        ))).await?;
                        report.reason = CloseReason::ProtocolViolation;
                        return Ok(());
                    }
                }
            }
            _ = idle_tick.tick() => {
                if last_activity.elapsed() >= context.limits.idle_timeout {
                    report.reason = CloseReason::Idle;
                    return Ok(());
                }
            }
        }
    }
}

/// Returns `Ok(false)` when the connection must close after the reply.
async fn handle_request<S>(
    socket: &mut WebSocketStream<S>,
    context: &SessionContext,
    authenticated: &Authenticated,
    bucket: &mut TokenBucket,
    text: &str,
) -> Result<bool, SessionError>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let request = match parse_request(text) {
        Ok(request) => request,
        Err(error) => {
            send_text(socket, failure_frame("", &error)).await?;
            return Ok(false);
        }
    };
    if request.version != PROTOCOL_VERSION {
        send_text(
            socket,
            failure_frame(
                &request.id,
                &ServerError::new(
                    ErrorCode::UnsupportedVersion,
                    format!("only protocol version {PROTOCOL_VERSION} is supported"),
                ),
            ),
        )
        .await?;
        return Ok(true);
    }
    if !bucket.take() {
        send_text(
            socket,
            failure_frame(
                &request.id,
                &ServerError::new(ErrorCode::RateLimited, "slow down and retry"),
            ),
        )
        .await?;
        return Ok(true);
    }
    let result = context
        .service
        .call(ServiceRequest::Command {
            account_id: authenticated.account_id.clone(),
            device_public_key: authenticated.device_public_key,
            command: request.command,
            now: unix_now(),
        })
        .await;
    let frame = match result {
        Ok(value) => {
            let frame = success_frame(&request.id, value);
            if frame.len() <= MAX_FRAME_BYTES {
                frame
            } else {
                failure_frame(
                    &request.id,
                    &ServerError::new(
                        ErrorCode::TooLarge,
                        "response exceeds frame budget; use a paged request",
                    ),
                )
            }
        }
        Err(error) => failure_frame(&request.id, &error),
    };
    send_text(socket, frame).await?;
    Ok(true)
}

/// Drive hello and authenticate. `Ok(None)` means the client was answered
/// with an error and the connection should close.
async fn authenticate<S>(
    socket: &mut WebSocketStream<S>,
    context: &SessionContext,
    report: &mut SessionReport,
) -> Result<Option<Authenticated>, SessionError>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let Some((hello_id, hello)) = next_request(socket, report).await? else {
        return Ok(None);
    };
    let device_public_key = match hello {
        Command::Hello {
            minimum_version,
            maximum_version,
            device_public_key,
        } => {
            if minimum_version > PROTOCOL_VERSION || maximum_version < PROTOCOL_VERSION {
                send_text(
                    socket,
                    failure_frame(
                        &hello_id,
                        &ServerError::new(
                            ErrorCode::UnsupportedVersion,
                            format!("this server speaks protocol version {PROTOCOL_VERSION}"),
                        ),
                    ),
                )
                .await?;
                report.reason = CloseReason::ProtocolViolation;
                return Ok(None);
            }
            match decode_key(&device_public_key) {
                Ok(key) => key,
                Err(_) => {
                    send_text(
                        socket,
                        failure_frame(
                            &hello_id,
                            &ServerError::new(
                                ErrorCode::InvalidRequest,
                                "device_public_key must be 64 hex characters",
                            ),
                        ),
                    )
                    .await?;
                    report.reason = CloseReason::ProtocolViolation;
                    return Ok(None);
                }
            }
        }
        _ => {
            send_text(
                socket,
                failure_frame(
                    &hello_id,
                    &ServerError::new(
                        ErrorCode::NotAuthenticated,
                        "send hello before any other request",
                    ),
                ),
            )
            .await?;
            report.reason = CloseReason::ProtocolViolation;
            return Ok(None);
        }
    };
    let challenge = random_challenge().map_err(|_| SessionError::Randomness)?;
    let server_public_key = context.identity.public_key();
    send_text(
        socket,
        success_frame(
            &hello_id,
            json!({
                "version": PROTOCOL_VERSION,
                "challenge": hex::encode(challenge),
                "server_public_key": hex::encode(server_public_key),
                "server_signature": hex::encode(context.identity.sign_hello(&challenge, &device_public_key)),
            }),
        ),
    )
    .await?;

    let Some((auth_id, authenticate)) = next_request(socket, report).await? else {
        return Ok(None);
    };
    let Command::Authenticate {
        signature,
        display_name,
        invite_code,
    } = authenticate
    else {
        send_text(
            socket,
            failure_frame(
                &auth_id,
                &ServerError::new(
                    ErrorCode::NotAuthenticated,
                    "send authenticate before any other request",
                ),
            ),
        )
        .await?;
        report.reason = CloseReason::ProtocolViolation;
        return Ok(None);
    };
    let verified = decode_signature(&signature).ok().and_then(|signature| {
        verify_device_signature(
            &server_public_key,
            &challenge,
            &device_public_key,
            &signature,
        )
        .ok()
    });
    if verified.is_none() {
        send_text(
            socket,
            failure_frame(
                &auth_id,
                &ServerError::new(
                    ErrorCode::InvalidSignature,
                    "the challenge signature did not verify for this device key",
                ),
            ),
        )
        .await?;
        report.reason = CloseReason::AuthenticationFailed;
        return Ok(None);
    }
    match context
        .service
        .call(ServiceRequest::Register {
            device_public_key,
            display_name,
            invite_code,
            now: unix_now(),
        })
        .await
    {
        Ok(result) => {
            let account_id = result
                .get("account_id")
                .and_then(serde_json::Value::as_str)
                .ok_or(SessionError::MalformedRegistration)?
                .to_owned();
            send_text(socket, success_frame(&auth_id, result)).await?;
            Ok(Some(Authenticated {
                account_id,
                device_public_key,
            }))
        }
        Err(error) => {
            send_text(socket, failure_frame(&auth_id, &error)).await?;
            report.reason = CloseReason::AuthenticationFailed;
            Ok(None)
        }
    }
}

async fn next_request<S>(
    socket: &mut WebSocketStream<S>,
    report: &mut SessionReport,
) -> Result<Option<(String, Command)>, SessionError>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    loop {
        let Some(message) = socket.next().await else {
            report.reason = CloseReason::ClientClosed;
            return Ok(None);
        };
        match message.map_err(SessionError::WebSocket)? {
            Message::Text(text) => {
                report.requests += 1;
                match parse_request(text.as_str()) {
                    Ok(request) if request.version == PROTOCOL_VERSION => {
                        return Ok(Some((request.id, request.command)));
                    }
                    Ok(request) => {
                        send_text(
                            socket,
                            failure_frame(
                                &request.id,
                                &ServerError::new(
                                    ErrorCode::UnsupportedVersion,
                                    format!(
                                        "only protocol version {PROTOCOL_VERSION} is supported"
                                    ),
                                ),
                            ),
                        )
                        .await?;
                        report.reason = CloseReason::ProtocolViolation;
                        return Ok(None);
                    }
                    Err(error) => {
                        send_text(socket, failure_frame("", &error)).await?;
                        report.reason = CloseReason::ProtocolViolation;
                        return Ok(None);
                    }
                }
            }
            Message::Ping(payload) => {
                socket
                    .send(Message::Pong(payload))
                    .await
                    .map_err(SessionError::WebSocket)?;
            }
            Message::Pong(_) => {}
            Message::Close(_) => {
                report.reason = CloseReason::ClientClosed;
                return Ok(None);
            }
            Message::Binary(_) | Message::Frame(_) => {
                send_text(
                    socket,
                    failure_frame(
                        "",
                        &ServerError::new(
                            ErrorCode::InvalidRequest,
                            "only JSON text frames are accepted",
                        ),
                    ),
                )
                .await?;
                report.reason = CloseReason::ProtocolViolation;
                return Ok(None);
            }
        }
    }
}

fn parse_request(text: &str) -> Result<Request, ServerError> {
    let request: Request = serde_json::from_str(text).map_err(|error| {
        ServerError::new(
            ErrorCode::InvalidRequest,
            format!("request is not a valid protocol frame: {error}"),
        )
    })?;
    if request.id.is_empty() || request.id.len() > MAX_REQUEST_ID_BYTES {
        return Err(ServerError::new(
            ErrorCode::InvalidRequest,
            "id is 1 to 64 bytes",
        ));
    }
    Ok(request)
}

async fn send_text<S>(socket: &mut WebSocketStream<S>, frame: String) -> Result<(), SessionError>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    if frame.len() > MAX_FRAME_BYTES {
        return Err(SessionError::Service(ServerError::new(
            ErrorCode::TooLarge,
            "outgoing frame exceeds wire budget",
        )));
    }
    socket
        .send(Message::Text(frame.into()))
        .await
        .map_err(SessionError::WebSocket)
}

fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|elapsed| elapsed.as_secs())
        .unwrap_or(0)
}

struct TokenBucket {
    tokens: u32,
    capacity: u32,
    per_second: u32,
    refilled: Instant,
}

impl TokenBucket {
    fn new(capacity: u32, per_second: u32) -> Self {
        Self {
            tokens: capacity,
            capacity,
            per_second,
            refilled: Instant::now(),
        }
    }

    fn take(&mut self) -> bool {
        let elapsed = self.refilled.elapsed();
        let refill = elapsed.as_millis() * u128::from(self.per_second) / 1000;
        if refill > 0 {
            let refill = u32::try_from(refill).unwrap_or(u32::MAX);
            self.tokens = self.tokens.saturating_add(refill).min(self.capacity);
            self.refilled = Instant::now();
        }
        if self.tokens == 0 {
            return false;
        }
        self.tokens -= 1;
        true
    }
}

#[derive(Debug)]
pub enum SessionError {
    AdmissionTimeout,
    AuthenticationTimeout,
    WebSocket(tungstenite::Error),
    Service(ServerError),
    Randomness,
    MalformedRegistration,
}

impl fmt::Display for SessionError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::AdmissionTimeout => formatter.write_str("WebSocket handshake timed out"),
            Self::AuthenticationTimeout => {
                formatter.write_str("client did not authenticate in time")
            }
            Self::WebSocket(error) => write!(formatter, "WebSocket failed: {error}"),
            Self::Service(error) => write!(formatter, "service failed: {error}"),
            Self::Randomness => formatter.write_str("operating system randomness unavailable"),
            Self::MalformedRegistration => {
                formatter.write_str("service returned a registration without an account id")
            }
        }
    }
}

impl Error for SessionError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::WebSocket(error) => Some(error),
            Self::Service(error) => Some(error),
            _ => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::TokenBucket;

    #[test]
    fn token_bucket_limits_bursts() {
        let mut bucket = TokenBucket::new(3, 1000);
        assert!(bucket.take());
        assert!(bucket.take());
        assert!(bucket.take());
        assert!(!bucket.take(), "burst exhausted before refill");
        std::thread::sleep(std::time::Duration::from_millis(20));
        assert!(bucket.take(), "refilled after a short wait");
    }
}
