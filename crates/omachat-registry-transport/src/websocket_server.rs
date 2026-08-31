use crate::{MAX_REGISTRY_MESSAGE_BYTES, RegistryService, RegistryServiceError};
use futures_util::{SinkExt, StreamExt};
use std::{error::Error, fmt};
use tokio::io::{AsyncRead, AsyncWrite};
use tokio_tungstenite::{
    accept_async_with_config,
    tungstenite::{self, Message, protocol::WebSocketConfig},
};

pub const MAX_REGISTRY_REQUESTS_PER_CONNECTION: usize = 64;

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
    let mut config = WebSocketConfig::default();
    config.max_message_size = Some(MAX_REGISTRY_MESSAGE_BYTES);
    config.max_frame_size = Some(MAX_REGISTRY_MESSAGE_BYTES);
    let mut socket = accept_async_with_config(stream, Some(config))
        .await
        .map_err(RegistryWebSocketServerError::Connection)?;
    let mut handled_requests = 0_usize;

    while let Some(message) = socket.next().await {
        match message.map_err(RegistryWebSocketServerError::Connection)? {
            Message::Binary(request) => {
                if request.len() > MAX_REGISTRY_MESSAGE_BYTES {
                    return Err(RegistryWebSocketServerError::MessageTooLarge);
                }
                if handled_requests >= MAX_REGISTRY_REQUESTS_PER_CONNECTION {
                    return Err(RegistryWebSocketServerError::RequestLimitExceeded);
                }
                handled_requests += 1;
                let response = service
                    .handle(&request, accepted_at())
                    .map_err(RegistryWebSocketServerError::Service)?;
                socket
                    .send(Message::Binary(response.into()))
                    .await
                    .map_err(RegistryWebSocketServerError::Connection)?;
            }
            Message::Ping(payload) => socket
                .send(Message::Pong(payload))
                .await
                .map_err(RegistryWebSocketServerError::Connection)?,
            Message::Pong(_) => {}
            Message::Close(_) => return Ok(()),
            Message::Text(_) | Message::Frame(_) => {
                return Err(RegistryWebSocketServerError::UnexpectedMessage);
            }
        }
    }
    Ok(())
}

#[derive(Debug)]
pub enum RegistryWebSocketServerError {
    Connection(tungstenite::Error),
    Service(RegistryServiceError),
    MessageTooLarge,
    UnexpectedMessage,
    RequestLimitExceeded,
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
            Self::RequestLimitExceeded => write!(
                formatter,
                "registry WebSocket exceeded {MAX_REGISTRY_REQUESTS_PER_CONNECTION} requests"
            ),
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
