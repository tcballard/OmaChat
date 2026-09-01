use crate::{MAX_REGISTRY_MESSAGE_BYTES, RegistryService, RegistryServiceError};
use futures_util::{SinkExt, StreamExt};
use std::{error::Error, fmt};
use tokio::io::{AsyncRead, AsyncWrite};
use tokio_tungstenite::{
    WebSocketStream, accept_async_with_config,
    tungstenite::{self, Message, protocol::WebSocketConfig},
};

pub const MAX_REGISTRY_REQUESTS_PER_CONNECTION: usize = 1;

/// A bounded binary request admitted before the authoritative service is
/// borrowed. Hosting code can accept many handshakes concurrently, apply its
/// connection/IP policy, then serialize only the short state-machine mutation.
pub struct PendingRegistryWebSocketRequest<S> {
    socket: WebSocketStream<S>,
    request: Vec<u8>,
}

impl<S> PendingRegistryWebSocketRequest<S>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    #[must_use]
    pub fn request(&self) -> &[u8] {
        &self.request
    }

    pub async fn respond(mut self, response: Vec<u8>) -> Result<(), RegistryWebSocketServerError> {
        if response.len() > MAX_REGISTRY_MESSAGE_BYTES {
            return Err(RegistryWebSocketServerError::MessageTooLarge);
        }
        self.socket
            .send(Message::Binary(response.into()))
            .await
            .map_err(RegistryWebSocketServerError::Connection)?;
        let _ = self.socket.close(None).await;
        Ok(())
    }
}

/// Complete the WebSocket handshake and admit exactly one bounded binary
/// registry request without borrowing registry state.
pub async fn accept_registry_websocket_request<S>(
    stream: S,
) -> Result<PendingRegistryWebSocketRequest<S>, RegistryWebSocketServerError>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let mut config = WebSocketConfig::default();
    config.max_message_size = Some(MAX_REGISTRY_MESSAGE_BYTES);
    config.max_frame_size = Some(MAX_REGISTRY_MESSAGE_BYTES);
    let mut socket = accept_async_with_config(stream, Some(config))
        .await
        .map_err(RegistryWebSocketServerError::Connection)?;

    while let Some(message) = socket.next().await {
        match message.map_err(RegistryWebSocketServerError::Connection)? {
            Message::Binary(request) => {
                if request.len() > MAX_REGISTRY_MESSAGE_BYTES {
                    return Err(RegistryWebSocketServerError::MessageTooLarge);
                }
                return Ok(PendingRegistryWebSocketRequest {
                    socket,
                    request: request.to_vec(),
                });
            }
            Message::Ping(payload) => socket
                .send(Message::Pong(payload))
                .await
                .map_err(RegistryWebSocketServerError::Connection)?,
            Message::Pong(_) => {}
            Message::Close(_) => return Err(RegistryWebSocketServerError::ClosedBeforeRequest),
            Message::Text(_) | Message::Frame(_) => {
                return Err(RegistryWebSocketServerError::UnexpectedMessage);
            }
        }
    }
    Err(RegistryWebSocketServerError::ClosedBeforeRequest)
}

/// Serve one already accepted registry WebSocket stream.
///
/// The hosting layer owns TCP binding, TLS termination, client/IP policy,
/// concurrency, and service locking. Passing a TLS-wrapped stream provides
/// end-to-end TLS; passing a plain stream is appropriate only behind a trusted
/// local reverse proxy or in hermetic tests.
pub async fn serve_registry_websocket_connection<S, C>(
    stream: S,
    service: &mut RegistryService<'_>,
    mut accepted_at: C,
) -> Result<(), RegistryWebSocketServerError>
where
    S: AsyncRead + AsyncWrite + Unpin,
    C: FnMut() -> u64,
{
    let pending = accept_registry_websocket_request(stream).await?;
    let response = service
        .handle(pending.request(), accepted_at())
        .map_err(RegistryWebSocketServerError::Service)?;
    pending.respond(response).await
}

#[derive(Debug)]
pub enum RegistryWebSocketServerError {
    Connection(tungstenite::Error),
    Service(RegistryServiceError),
    MessageTooLarge,
    UnexpectedMessage,
    ClosedBeforeRequest,
}

impl fmt::Display for RegistryWebSocketServerError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Connection(error) => write!(formatter, "registry WebSocket failed: {error}"),
            Self::Service(error) => write!(formatter, "registry service failed: {error}"),
            Self::MessageTooLarge => write!(
                formatter,
                "registry WebSocket message exceeds {MAX_REGISTRY_MESSAGE_BYTES} bytes"
            ),
            Self::UnexpectedMessage => {
                formatter.write_str("registry WebSocket received a non-binary request")
            }
            Self::ClosedBeforeRequest => {
                formatter.write_str("registry WebSocket closed before a request was admitted")
            }
        }
    }
}

impl Error for RegistryWebSocketServerError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Connection(error) => Some(error),
            Self::Service(error) => Some(error),
            _ => None,
        }
    }
}
