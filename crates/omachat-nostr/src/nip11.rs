//! Strict NIP-11 relay information documents and a bounded fetcher.
//!
//! The relay's information document is the standard place a relay states its
//! own public key. That key, not the URL, is what OmaChat binds room identity
//! to. A missing or malformed key is reported, never guessed, and a fetched
//! document is bounded in size before it is parsed.

use crate::relay::RelayRoute;
use rustls::{ClientConfig, RootCertStore};
use rustls_pki_types::ServerName;
use serde_json::Value;
use std::{error::Error, fmt, future::Future, sync::Arc, time::Duration};
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt},
    net::TcpStream,
    time::timeout,
};
use tokio_rustls::TlsConnector;
use tokio_socks::tcp::Socks5Stream;
use url::Url;

pub const NIP11_ACCEPT: &str = "application/nostr+json";

/// Bounds applied to every information document before interpretation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RelayInformationLimits {
    pub max_document_bytes: usize,
    pub max_field_bytes: usize,
    pub max_supported_nips: usize,
}

impl Default for RelayInformationLimits {
    fn default() -> Self {
        Self {
            max_document_bytes: 64 * 1024,
            max_field_bytes: 4096,
            max_supported_nips: 256,
        }
    }
}

/// The subset of a NIP-11 document OmaChat relies on. Unknown fields are
/// ignored; known fields with the wrong shape fail closed.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RelayInformation {
    name: Option<String>,
    description: Option<String>,
    pubkey: Option<String>,
    contact: Option<String>,
    supported_nips: Vec<u32>,
    software: Option<String>,
    version: Option<String>,
    auth_required: Option<bool>,
    max_subscriptions: Option<u64>,
}

impl RelayInformation {
    pub fn from_json(
        bytes: &[u8],
        limits: &RelayInformationLimits,
    ) -> Result<Self, RelayInformationError> {
        if bytes.len() > limits.max_document_bytes {
            return Err(RelayInformationError::DocumentTooLarge {
                bytes: bytes.len(),
                maximum: limits.max_document_bytes,
            });
        }
        let document: Value =
            serde_json::from_slice(bytes).map_err(|_| RelayInformationError::MalformedJson)?;
        let Value::Object(fields) = document else {
            return Err(RelayInformationError::NotAnObject);
        };

        let text = |name: &'static str| -> Result<Option<String>, RelayInformationError> {
            match fields.get(name) {
                None | Some(Value::Null) => Ok(None),
                Some(Value::String(value)) => {
                    if value.len() > limits.max_field_bytes {
                        return Err(RelayInformationError::FieldTooLarge(name));
                    }
                    Ok(Some(value.clone()))
                }
                Some(_) => Err(RelayInformationError::InvalidField(name)),
            }
        };

        let pubkey = match text("pubkey")? {
            None => None,
            Some(value) if value.is_empty() => None,
            Some(value) => {
                if !is_lowercase_hex(&value, 64) {
                    return Err(RelayInformationError::InvalidPublicKey);
                }
                Some(value)
            }
        };

        let mut supported_nips = Vec::new();
        match fields.get("supported_nips") {
            None | Some(Value::Null) => {}
            Some(Value::Array(values)) => {
                if values.len() > limits.max_supported_nips {
                    return Err(RelayInformationError::FieldTooLarge("supported_nips"));
                }
                for value in values {
                    let nip = value
                        .as_u64()
                        .and_then(|nip| u32::try_from(nip).ok())
                        .ok_or(RelayInformationError::InvalidField("supported_nips"))?;
                    if !supported_nips.contains(&nip) {
                        supported_nips.push(nip);
                    }
                }
            }
            Some(_) => return Err(RelayInformationError::InvalidField("supported_nips")),
        }

        let (auth_required, max_subscriptions) = match fields.get("limitation") {
            None | Some(Value::Null) => (None, None),
            Some(Value::Object(limitation)) => {
                let auth_required = match limitation.get("auth_required") {
                    None | Some(Value::Null) => None,
                    Some(Value::Bool(value)) => Some(*value),
                    Some(_) => return Err(RelayInformationError::InvalidField("auth_required")),
                };
                let max_subscriptions = match limitation.get("max_subscriptions") {
                    None | Some(Value::Null) => None,
                    Some(value) => Some(
                        value
                            .as_u64()
                            .ok_or(RelayInformationError::InvalidField("max_subscriptions"))?,
                    ),
                };
                (auth_required, max_subscriptions)
            }
            Some(_) => return Err(RelayInformationError::InvalidField("limitation")),
        };

        Ok(Self {
            name: text("name")?,
            description: text("description")?,
            pubkey,
            contact: text("contact")?,
            supported_nips,
            software: text("software")?,
            version: text("version")?,
            auth_required,
            max_subscriptions,
        })
    }

    #[must_use]
    pub fn name(&self) -> Option<&str> {
        self.name.as_deref()
    }

    #[must_use]
    pub fn description(&self) -> Option<&str> {
        self.description.as_deref()
    }

    /// The relay's self-declared public key, if it declared one.
    #[must_use]
    pub fn pubkey(&self) -> Option<&str> {
        self.pubkey.as_deref()
    }

    #[must_use]
    pub fn contact(&self) -> Option<&str> {
        self.contact.as_deref()
    }

    #[must_use]
    pub fn supported_nips(&self) -> &[u32] {
        &self.supported_nips
    }

    #[must_use]
    pub fn supports_nip(&self, nip: u32) -> bool {
        self.supported_nips.contains(&nip)
    }

    #[must_use]
    pub fn software(&self) -> Option<&str> {
        self.software.as_deref()
    }

    #[must_use]
    pub fn version(&self) -> Option<&str> {
        self.version.as_deref()
    }

    #[must_use]
    pub const fn auth_required(&self) -> Option<bool> {
        self.auth_required
    }

    #[must_use]
    pub const fn max_subscriptions(&self) -> Option<u64> {
        self.max_subscriptions
    }
}

/// Anything that can produce a relay's information document for a relay URL.
///
/// Tests supply deterministic fakes; production uses
/// [`HttpRelayInformationFetcher`].
pub trait RelayInformationSource {
    fn fetch(
        &self,
        relay_url: &str,
    ) -> impl Future<Output = Result<RelayInformation, RelayInformationError>> + Send;
}

/// Minimal HTTP/1.1 `GET` with `Accept: application/nostr+json` over the
/// same direct or SOCKS5 route the relay socket uses. Redirects are not
/// followed and the response is bounded before it is parsed.
#[derive(Clone, Debug)]
pub struct HttpRelayInformationFetcher {
    route: RelayRoute,
    timeout: Duration,
    limits: RelayInformationLimits,
}

const MAX_HEADER_BYTES: usize = 16 * 1024;

impl HttpRelayInformationFetcher {
    #[must_use]
    pub fn new(route: RelayRoute, timeout: Duration, limits: RelayInformationLimits) -> Self {
        Self {
            route,
            timeout,
            limits,
        }
    }

    async fn fetch_inner(
        &self,
        relay_url: &str,
    ) -> Result<RelayInformation, RelayInformationError> {
        let url = Url::parse(relay_url).map_err(|_| RelayInformationError::InvalidUrl)?;
        let tls = match url.scheme() {
            "wss" | "https" => true,
            "ws" | "http" => false,
            _ => return Err(RelayInformationError::InvalidUrl),
        };
        let host = url
            .host_str()
            .ok_or(RelayInformationError::InvalidUrl)?
            .to_owned();
        let port = url
            .port_or_known_default()
            .ok_or(RelayInformationError::InvalidUrl)?;
        let mut path = url.path().to_owned();
        if path.is_empty() {
            path.push('/');
        }
        if let Some(query) = url.query() {
            path.push('?');
            path.push_str(query);
        }
        let host_header = match url.port() {
            Some(port) => format!("{host}:{port}"),
            None => host.clone(),
        };
        let request = format!(
            "GET {path} HTTP/1.1\r\nHost: {host_header}\r\nAccept: {NIP11_ACCEPT}\r\nUser-Agent: omachat\r\nConnection: close\r\n\r\n"
        );

        let raw = match &self.route {
            RelayRoute::Direct => Box::new(
                TcpStream::connect((host.as_str(), port))
                    .await
                    .map_err(|error| RelayInformationError::Io(error.to_string()))?,
            ) as Box<dyn Io>,
            RelayRoute::Socks5(proxy) => Box::new(
                Socks5Stream::connect(proxy.as_str(), (host.as_str(), port))
                    .await
                    .map_err(|error| RelayInformationError::Socks(error.to_string()))?,
            ),
        };
        let response = if tls {
            let server_name = ServerName::try_from(host.clone())
                .map_err(|_| RelayInformationError::InvalidUrl)?;
            let connector = TlsConnector::from(native_tls_config()?);
            let stream = connector
                .connect(server_name, raw)
                .await
                .map_err(|error| RelayInformationError::Tls(error.to_string()))?;
            exchange(stream, request.as_bytes(), &self.limits).await?
        } else {
            exchange(raw, request.as_bytes(), &self.limits).await?
        };
        RelayInformation::from_json(&response, &self.limits)
    }
}

impl RelayInformationSource for HttpRelayInformationFetcher {
    async fn fetch(&self, relay_url: &str) -> Result<RelayInformation, RelayInformationError> {
        timeout(self.timeout, self.fetch_inner(relay_url))
            .await
            .map_err(|_| RelayInformationError::Timeout)?
    }
}

trait Io: AsyncRead + AsyncWrite + Send + Unpin {}
impl<T: AsyncRead + AsyncWrite + Send + Unpin> Io for T {}

fn native_tls_config() -> Result<Arc<ClientConfig>, RelayInformationError> {
    let mut roots = RootCertStore::empty();
    let certificates = rustls_native_certs::load_native_certs();
    let (added, _) = roots.add_parsable_certificates(certificates.certs);
    if added == 0 {
        return Err(RelayInformationError::Tls(
            "no native root certificates available".to_owned(),
        ));
    }
    Ok(Arc::new(
        ClientConfig::builder()
            .with_root_certificates(roots)
            .with_no_client_auth(),
    ))
}

async fn exchange<S: AsyncRead + AsyncWrite + Unpin>(
    mut stream: S,
    request: &[u8],
    limits: &RelayInformationLimits,
) -> Result<Vec<u8>, RelayInformationError> {
    stream
        .write_all(request)
        .await
        .map_err(|error| RelayInformationError::Io(error.to_string()))?;
    let cap = MAX_HEADER_BYTES + limits.max_document_bytes;
    let mut buffer = Vec::new();
    let mut chunk = [0_u8; 4096];
    loop {
        let read = stream
            .read(&mut chunk)
            .await
            .map_err(|error| RelayInformationError::Io(error.to_string()))?;
        if read == 0 {
            return try_complete(&buffer, true, limits)?
                .ok_or(RelayInformationError::MalformedResponse);
        }
        buffer.extend_from_slice(&chunk[..read]);
        if buffer.len() > cap {
            return Err(RelayInformationError::ResponseTooLarge);
        }
        if let Some(body) = try_complete(&buffer, false, limits)? {
            return Ok(body);
        }
    }
}

/// Returns the body once the response is provably complete. A response
/// without length framing is complete only at EOF.
fn try_complete(
    buffer: &[u8],
    eof: bool,
    limits: &RelayInformationLimits,
) -> Result<Option<Vec<u8>>, RelayInformationError> {
    let Some(split) = find(buffer, b"\r\n\r\n") else {
        if buffer.len() > MAX_HEADER_BYTES {
            return Err(RelayInformationError::ResponseTooLarge);
        }
        return Ok(None);
    };
    let head = std::str::from_utf8(&buffer[..split])
        .map_err(|_| RelayInformationError::MalformedResponse)?;
    let mut lines = head.split("\r\n");
    let status_line = lines
        .next()
        .ok_or(RelayInformationError::MalformedResponse)?;
    let mut parts = status_line.splitn(3, ' ');
    let version = parts.next().unwrap_or_default();
    if !matches!(version, "HTTP/1.1" | "HTTP/1.0") {
        return Err(RelayInformationError::MalformedResponse);
    }
    let status = parts
        .next()
        .and_then(|code| code.parse::<u16>().ok())
        .ok_or(RelayInformationError::MalformedResponse)?;
    let mut content_length = None;
    let mut chunked = false;
    for line in lines {
        let Some((name, value)) = line.split_once(':') else {
            return Err(RelayInformationError::MalformedResponse);
        };
        let value = value.trim();
        if name.eq_ignore_ascii_case("content-length") {
            content_length = Some(
                value
                    .parse::<usize>()
                    .map_err(|_| RelayInformationError::MalformedResponse)?,
            );
        } else if name.eq_ignore_ascii_case("transfer-encoding")
            && value.to_ascii_lowercase().contains("chunked")
        {
            chunked = true;
        }
    }
    let body = &buffer[split + 4..];
    let body = if chunked {
        match decode_chunked(body)? {
            Some(body) => body,
            None => return Ok(None),
        }
    } else if let Some(length) = content_length {
        if body.len() < length {
            return Ok(None);
        }
        body[..length].to_vec()
    } else if eof {
        body.to_vec()
    } else {
        return Ok(None);
    };
    if status != 200 {
        return Err(RelayInformationError::HttpStatus(status));
    }
    if body.len() > limits.max_document_bytes {
        return Err(RelayInformationError::ResponseTooLarge);
    }
    Ok(Some(body))
}

fn decode_chunked(mut body: &[u8]) -> Result<Option<Vec<u8>>, RelayInformationError> {
    let mut decoded = Vec::new();
    loop {
        let Some(line_end) = find(body, b"\r\n") else {
            return Ok(None);
        };
        let size_line = std::str::from_utf8(&body[..line_end])
            .map_err(|_| RelayInformationError::MalformedResponse)?;
        let size_hex = size_line.split(';').next().unwrap_or_default().trim();
        let size = usize::from_str_radix(size_hex, 16)
            .map_err(|_| RelayInformationError::MalformedResponse)?;
        body = &body[line_end + 2..];
        if size == 0 {
            return Ok(Some(decoded));
        }
        if body.len() < size + 2 {
            return Ok(None);
        }
        decoded.extend_from_slice(&body[..size]);
        if &body[size..size + 2] != b"\r\n" {
            return Err(RelayInformationError::MalformedResponse);
        }
        body = &body[size + 2..];
    }
}

fn find(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack
        .windows(needle.len())
        .position(|window| window == needle)
}

fn is_lowercase_hex(value: &str, len: usize) -> bool {
    value.len() == len
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum RelayInformationError {
    InvalidUrl,
    Timeout,
    Io(String),
    Socks(String),
    Tls(String),
    HttpStatus(u16),
    MalformedResponse,
    ResponseTooLarge,
    DocumentTooLarge { bytes: usize, maximum: usize },
    MalformedJson,
    NotAnObject,
    InvalidField(&'static str),
    FieldTooLarge(&'static str),
    InvalidPublicKey,
}

impl fmt::Display for RelayInformationError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidUrl => formatter.write_str("relay URL must be ws:// or wss://"),
            Self::Timeout => formatter.write_str("NIP-11 fetch timed out"),
            Self::Io(error) => write!(formatter, "NIP-11 fetch I/O failed: {error}"),
            Self::Socks(error) => write!(formatter, "NIP-11 fetch SOCKS5 failed: {error}"),
            Self::Tls(error) => write!(formatter, "NIP-11 fetch TLS failed: {error}"),
            Self::HttpStatus(status) => write!(formatter, "NIP-11 fetch returned HTTP {status}"),
            Self::MalformedResponse => {
                formatter.write_str("NIP-11 response was not valid HTTP/1.1")
            }
            Self::ResponseTooLarge => formatter.write_str("NIP-11 response exceeded its bound"),
            Self::DocumentTooLarge { bytes, maximum } => write!(
                formatter,
                "NIP-11 document is {bytes} bytes but at most {maximum} are allowed"
            ),
            Self::MalformedJson => formatter.write_str("NIP-11 document is not valid JSON"),
            Self::NotAnObject => formatter.write_str("NIP-11 document must be a JSON object"),
            Self::InvalidField(name) => {
                write!(formatter, "NIP-11 field {name} has the wrong shape")
            }
            Self::FieldTooLarge(name) => write!(formatter, "NIP-11 field {name} exceeds its bound"),
            Self::InvalidPublicKey => {
                formatter.write_str("NIP-11 relay pubkey must be a lowercase 32-byte public key")
            }
        }
    }
}

impl Error for RelayInformationError {}
