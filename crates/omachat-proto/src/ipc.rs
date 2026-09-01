//! Versioned, bounded JSON-lines IPC contract shared by daemon clients.

use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::{error::Error, fmt};

pub const VERSION: u16 = 1;
pub const MAX_LINE_BYTES: usize = 64 * 1024;
pub const MAX_CORRELATION_ID_BYTES: usize = 128;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Request {
    pub version: u16,
    pub id: String,
    pub command: Command,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "method", content = "params", rename_all = "kebab-case")]
pub enum Command {
    Hello {
        minimum_version: u16,
        maximum_version: u16,
    },
    Status,
    Fingerprint,
    Join {
        geohash: String,
    },
    Leave {
        geohash: String,
    },
    Send {
        conversation: String,
        text: String,
    },
    DiscoverDmRelays {
        public_key: String,
    },
    DiscoverProfile {
        public_key: String,
    },
    ShowProfile {
        public_key: String,
    },
    ResolveRegistryHandle {
        handle: String,
    },
    ShowRegistryHandle {
        handle: String,
    },
    ClaimRegistryHandle {
        handle: String,
        confirmation: String,
    },
    Who {
        geohash: String,
    },
    Block {
        public_key: String,
    },
    Panic {
        confirmation: String,
    },
    Subscribe {
        topics: Vec<Topic>,
    },
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum Topic {
    Status,
    Conversations,
    Messages,
    Presence,
    Delivery,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Response {
    pub version: u16,
    pub id: String,
    pub outcome: ResponseOutcome,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "status", rename_all = "kebab-case")]
pub enum ResponseOutcome {
    Ok { result: Value },
    Error { error: ErrorBody },
}

#[derive(Serialize)]
struct FlatRequestRef<'a> {
    version: u16,
    id: &'a str,
    #[serde(flatten)]
    command: &'a Command,
}

#[derive(Deserialize)]
#[serde(tag = "method", rename_all = "kebab-case", deny_unknown_fields)]
enum StrictRequestWire {
    Hello {
        version: u16,
        id: String,
        params: HelloParams,
    },
    Status {
        version: u16,
        id: String,
    },
    Fingerprint {
        version: u16,
        id: String,
    },
    Join {
        version: u16,
        id: String,
        params: GeohashParams,
    },
    Leave {
        version: u16,
        id: String,
        params: GeohashParams,
    },
    Send {
        version: u16,
        id: String,
        params: SendParams,
    },
    DiscoverDmRelays {
        version: u16,
        id: String,
        params: PublicKeyParams,
    },
    DiscoverProfile {
        version: u16,
        id: String,
        params: PublicKeyParams,
    },
    ShowProfile {
        version: u16,
        id: String,
        params: PublicKeyParams,
    },
    ResolveRegistryHandle {
        version: u16,
        id: String,
        params: HandleParams,
    },
    ShowRegistryHandle {
        version: u16,
        id: String,
        params: HandleParams,
    },
    ClaimRegistryHandle {
        version: u16,
        id: String,
        params: RegistryClaimParams,
    },
    Who {
        version: u16,
        id: String,
        params: GeohashParams,
    },
    Block {
        version: u16,
        id: String,
        params: PublicKeyParams,
    },
    Panic {
        version: u16,
        id: String,
        params: ConfirmationParams,
    },
    Subscribe {
        version: u16,
        id: String,
        params: SubscribeParams,
    },
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct HelloParams {
    minimum_version: u16,
    maximum_version: u16,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct GeohashParams {
    geohash: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct SendParams {
    conversation: String,
    text: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct PublicKeyParams {
    public_key: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct HandleParams {
    handle: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RegistryClaimParams {
    handle: String,
    confirmation: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ConfirmationParams {
    confirmation: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct SubscribeParams {
    topics: Vec<Topic>,
}

impl From<StrictRequestWire> for Request {
    fn from(wire: StrictRequestWire) -> Self {
        let (version, id, command) = match wire {
            StrictRequestWire::Hello {
                version,
                id,
                params:
                    HelloParams {
                        minimum_version,
                        maximum_version,
                    },
            } => (
                version,
                id,
                Command::Hello {
                    minimum_version,
                    maximum_version,
                },
            ),
            StrictRequestWire::Status { version, id } => (version, id, Command::Status),
            StrictRequestWire::Fingerprint { version, id } => (version, id, Command::Fingerprint),
            StrictRequestWire::Join {
                version,
                id,
                params: GeohashParams { geohash },
            } => (version, id, Command::Join { geohash }),
            StrictRequestWire::Leave {
                version,
                id,
                params: GeohashParams { geohash },
            } => (version, id, Command::Leave { geohash }),
            StrictRequestWire::Send {
                version,
                id,
                params: SendParams { conversation, text },
            } => (version, id, Command::Send { conversation, text }),
            StrictRequestWire::DiscoverDmRelays {
                version,
                id,
                params: PublicKeyParams { public_key },
            } => (version, id, Command::DiscoverDmRelays { public_key }),
            StrictRequestWire::DiscoverProfile {
                version,
                id,
                params: PublicKeyParams { public_key },
            } => (version, id, Command::DiscoverProfile { public_key }),
            StrictRequestWire::ShowProfile {
                version,
                id,
                params: PublicKeyParams { public_key },
            } => (version, id, Command::ShowProfile { public_key }),
            StrictRequestWire::ResolveRegistryHandle {
                version,
                id,
                params: HandleParams { handle },
            } => (version, id, Command::ResolveRegistryHandle { handle }),
            StrictRequestWire::ShowRegistryHandle {
                version,
                id,
                params: HandleParams { handle },
            } => (version, id, Command::ShowRegistryHandle { handle }),
            StrictRequestWire::ClaimRegistryHandle {
                version,
                id,
                params:
                    RegistryClaimParams {
                        handle,
                        confirmation,
                    },
            } => (
                version,
                id,
                Command::ClaimRegistryHandle {
                    handle,
                    confirmation,
                },
            ),
            StrictRequestWire::Who {
                version,
                id,
                params: GeohashParams { geohash },
            } => (version, id, Command::Who { geohash }),
            StrictRequestWire::Block {
                version,
                id,
                params: PublicKeyParams { public_key },
            } => (version, id, Command::Block { public_key }),
            StrictRequestWire::Panic {
                version,
                id,
                params: ConfirmationParams { confirmation },
            } => (version, id, Command::Panic { confirmation }),
            StrictRequestWire::Subscribe {
                version,
                id,
                params: SubscribeParams { topics },
            } => (version, id, Command::Subscribe { topics }),
        };
        Self {
            version,
            id,
            command,
        }
    }
}

impl Serialize for Request {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        FlatRequestRef {
            version: self.version,
            id: &self.id,
            command: &self.command,
        }
        .serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for Request {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        StrictRequestWire::deserialize(deserializer).map(Self::from)
    }
}

#[derive(Serialize)]
struct FlatResponseRef<'a> {
    version: u16,
    id: &'a str,
    #[serde(flatten)]
    outcome: &'a ResponseOutcome,
}

#[derive(Deserialize)]
#[serde(tag = "status", rename_all = "kebab-case", deny_unknown_fields)]
enum StrictResponseWire {
    Ok {
        version: u16,
        id: String,
        result: Value,
    },
    Error {
        version: u16,
        id: String,
        error: ErrorBody,
    },
}

impl From<StrictResponseWire> for Response {
    fn from(wire: StrictResponseWire) -> Self {
        match wire {
            StrictResponseWire::Ok {
                version,
                id,
                result,
            } => Self {
                version,
                id,
                outcome: ResponseOutcome::Ok { result },
            },
            StrictResponseWire::Error { version, id, error } => Self {
                version,
                id,
                outcome: ResponseOutcome::Error { error },
            },
        }
    }
}

impl Serialize for Response {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        FlatResponseRef {
            version: self.version,
            id: &self.id,
            outcome: &self.outcome,
        }
        .serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for Response {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        StrictResponseWire::deserialize(deserializer).map(Self::from)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ErrorBody {
    pub code: ErrorCode,
    pub message: String,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum ErrorCode {
    InvalidRequest,
    VersionMismatch,
    NotFound,
    Conflict,
    Unavailable,
    Internal,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Event {
    pub version: u16,
    pub sequence: u64,
    pub topic: Topic,
    pub payload: Value,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct HelloResult {
    pub version: u16,
}

pub fn negotiate(minimum: u16, maximum: u16) -> Result<HelloResult, IpcError> {
    if minimum <= VERSION && VERSION <= maximum {
        Ok(HelloResult { version: VERSION })
    } else {
        Err(IpcError::VersionMismatch {
            minimum,
            maximum,
            supported: VERSION,
        })
    }
}

/// Incremental decoder that rejects a line before retaining more than its cap.
pub struct RequestDecoder {
    buffer: Vec<u8>,
    maximum: usize,
}

impl Default for RequestDecoder {
    fn default() -> Self {
        Self::new(MAX_LINE_BYTES)
    }
}

impl RequestDecoder {
    #[must_use]
    pub fn new(maximum: usize) -> Self {
        Self {
            buffer: Vec::new(),
            maximum,
        }
    }

    pub fn push(&mut self, bytes: &[u8]) -> Result<Vec<Request>, IpcError> {
        if self.buffer.len().saturating_add(bytes.len()) > self.maximum
            && !bytes
                .iter()
                .take(self.maximum.saturating_sub(self.buffer.len()) + 1)
                .any(|byte| *byte == b'\n')
        {
            self.buffer.clear();
            return Err(IpcError::LineTooLarge {
                maximum: self.maximum,
            });
        }
        self.buffer.extend_from_slice(bytes);
        let mut decoded = Vec::new();
        while let Some(newline) = self.buffer.iter().position(|byte| *byte == b'\n') {
            if newline > self.maximum {
                self.buffer.drain(..=newline);
                return Err(IpcError::LineTooLarge {
                    maximum: self.maximum,
                });
            }
            let mut line = self.buffer.drain(..=newline).collect::<Vec<_>>();
            line.pop();
            if line.last() == Some(&b'\r') {
                line.pop();
            }
            let request: Request =
                serde_json::from_slice(&line).map_err(|_| IpcError::MalformedJson)?;
            validate_request(&request)?;
            decoded.push(request);
        }
        if self.buffer.len() > self.maximum {
            self.buffer.clear();
            return Err(IpcError::LineTooLarge {
                maximum: self.maximum,
            });
        }
        Ok(decoded)
    }

    pub fn finish(self) -> Result<(), IpcError> {
        if self.buffer.is_empty() {
            Ok(())
        } else {
            Err(IpcError::TruncatedLine)
        }
    }
}

pub fn encode_line<T: Serialize>(message: &T) -> Result<Vec<u8>, IpcError> {
    let mut encoded = serde_json::to_vec(message).map_err(|_| IpcError::Encoding)?;
    if encoded.len() > MAX_LINE_BYTES {
        return Err(IpcError::LineTooLarge {
            maximum: MAX_LINE_BYTES,
        });
    }
    encoded.push(b'\n');
    Ok(encoded)
}

fn validate_request(request: &Request) -> Result<(), IpcError> {
    if request.version != VERSION {
        return Err(IpcError::UnsupportedVersion(request.version));
    }
    if request.id.is_empty()
        || request.id.len() > MAX_CORRELATION_ID_BYTES
        || request.id.chars().any(char::is_control)
    {
        return Err(IpcError::InvalidCorrelationId);
    }
    Ok(())
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum IpcError {
    LineTooLarge {
        maximum: usize,
    },
    MalformedJson,
    TruncatedLine,
    Encoding,
    InvalidCorrelationId,
    UnsupportedVersion(u16),
    VersionMismatch {
        minimum: u16,
        maximum: u16,
        supported: u16,
    },
}

impl fmt::Display for IpcError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::LineTooLarge { maximum } => {
                write!(formatter, "IPC line exceeds {maximum} bytes")
            }
            Self::MalformedJson => formatter.write_str("IPC line is malformed JSON"),
            Self::TruncatedLine => formatter.write_str("IPC stream ended inside a line"),
            Self::Encoding => formatter.write_str("IPC message encoding failed"),
            Self::InvalidCorrelationId => formatter.write_str("IPC correlation ID is invalid"),
            Self::UnsupportedVersion(version) => {
                write!(formatter, "unsupported IPC version {version}")
            }
            Self::VersionMismatch {
                minimum,
                maximum,
                supported,
            } => write!(
                formatter,
                "IPC versions {minimum}..={maximum} do not include supported version {supported}"
            ),
        }
    }
}

impl Error for IpcError {}
