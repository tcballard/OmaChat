use crate::{MAX_REGISTRY_MESSAGE_BYTES, RegistryTransport};
use futures_util::{SinkExt, StreamExt};
use std::{error::Error, fmt, future::Future, net::IpAddr, pin::Pin};
use tokio_tungstenite::{
    connect_async_with_config,
    tungstenite::{self, Message, protocol::WebSocketConfig},
};
use url::Url;

/// One-request-per-connection WSS transport for the central registry protocol.
///
/// Short-lived connections avoid ambiguous shared-stream state during early
/// deployment. Registry claims remain safely retryable through their signed
/// idempotency command IDs. Remote plaintext WebSockets are rejected; `ws://`
/// is accepted only for loopback development and hermetic tests.
#[derive(Clone, Debug)]
pub struct RegistryWebSocketTransport {
    endpoint: Url,
}

impl RegistryWebSocketTransport {
    pub fn new(endpoint: &str) -> Result<Self, RegistryWebSocketError> {
        let endpoint = Url::parse(endpoint).map_err(|_| RegistryWebSocketError::InvalidEndpoint)?;
        if !endpoint.username().is_empty() || endpoint.password().is_some() {
            return Err(RegistryWebSocketError::CredentialsNotAllowed);
        }
        if endpoint.query().is_some() || endpoint.fragment().is_some() {
            return Err(RegistryWebSocketError::QueryOrFragmentNotAllowed);
        }
        let host = endpoint
            .host_str()
            .ok_or(RegistryWebSocketError::InvalidEndpoint)?;
        match endpoint.scheme() {
            "wss" => {}
            "ws" if is_loopback(host) => {}
            "ws" => return Err(RegistryWebSocketError::InsecureRemoteEndpoint),
            _ => return Err(RegistryWebSocketError::UnsupportedScheme),
        }
        Ok(Self { endpoint })
    }

    #[must_use]
    pub fn endpoint(&self) -> &str {
        self.endpoint.as_str()
    }
}

impl RegistryTransport for RegistryWebSocketTransport {
    type Error = RegistryWebSocketError;
    type Exchange<'a>
        = Pin<Box<dyn Future<Output = Result<Vec<u8>, Self::Error>> + Send + 'a>>
    where
        Self: 'a;

    fn exchange(&mut self, request: Vec<u8>) -> Self::Exchange<'_> {
        let endpoint = self.endpoint.clone();
        Box::pin(async move {
            if request.len() > MAX_REGISTRY_MESSAGE_BYTES {
                return Err(RegistryWebSocketError::MessageTooLarge);
            }

            let mut config = WebSocketConfig::default();
            config.max_message_size = Some(MAX_REGISTRY_MESSAGE_BYTES);
            config.max_frame_size = Some(MAX_REGISTRY_MESSAGE_BYTES);
            let (mut socket, _) = connect_async_with_config(endpoint.as_str(), Some(config), false)
                .await
                .map_err(RegistryWebSocketError::Connection)?;
            socket
                .send(Message::Binary(request.into()))
                .await
                .map_err(RegistryWebSocketError::Connection)?;

            while let Some(message) = socket.next().await {
                match message.map_err(RegistryWebSocketError::Connection)? {
                    Message::Binary(response) => {
                        if response.len() > MAX_REGISTRY_MESSAGE_BYTES {
                            return Err(RegistryWebSocketError::MessageTooLarge);
                        }
                        let response = response.to_vec();
                        let _ = socket.close(None).await;
                        return Ok(response);
                    }
                    Message::Ping(payload) => socket
                        .send(Message::Pong(payload))
                        .await
                        .map_err(RegistryWebSocketError::Connection)?,
                    Message::Pong(_) => {}
                    Message::Close(_) => return Err(RegistryWebSocketError::Closed),
                    Message::Text(_) | Message::Frame(_) => {
                        return Err(RegistryWebSocketError::UnexpectedMessage);
                    }
                }
            }
            Err(RegistryWebSocketError::Closed)
        })
    }
}

fn is_loopback(host: &str) -> bool {
    let host = host
        .strip_prefix('[')
        .and_then(|host| host.strip_suffix(']'))
        .unwrap_or(host);
    host.eq_ignore_ascii_case("localhost")
        || host
            .parse::<IpAddr>()
            .is_ok_and(|address| address.is_loopback())
}

#[derive(Debug)]
pub enum RegistryWebSocketError {
    InvalidEndpoint,
    UnsupportedScheme,
    InsecureRemoteEndpoint,
    CredentialsNotAllowed,
    QueryOrFragmentNotAllowed,
    MessageTooLarge,
    UnexpectedMessage,
    Closed,
    Connection(tungstenite::Error),
}

impl fmt::Display for RegistryWebSocketError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidEndpoint => formatter.write_str("registry WebSocket endpoint is invalid"),
            Self::UnsupportedScheme => formatter.write_str("registry endpoint must use wss://"),
            Self::InsecureRemoteEndpoint => {
                formatter.write_str("plaintext registry WebSockets are allowed only on loopback")
            }
            Self::CredentialsNotAllowed => {
                formatter.write_str("registry endpoint URL credentials are not allowed")
            }
            Self::QueryOrFragmentNotAllowed => {
                formatter.write_str("registry endpoint query strings and fragments are not allowed")
            }
            Self::MessageTooLarge => write!(
                formatter,
                "registry WebSocket message exceeds {MAX_REGISTRY_MESSAGE_BYTES} bytes"
            ),
            Self::UnexpectedMessage => {
                formatter.write_str("registry WebSocket returned a non-binary message")
            }
            Self::Closed => {
                formatter.write_str("registry WebSocket closed before returning a response")
            }
            Self::Connection(error) => write!(formatter, "registry WebSocket failed: {error}"),
        }
    }
}

impl Error for RegistryWebSocketError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Connection(error) => Some(error),
            _ => None,
        }
    }
}
