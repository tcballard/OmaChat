//! Bounded IPC client used by the scripting command.

use omachat_proto::ipc::{
    Command, Event, MAX_LINE_BYTES, Request, Response, ResponseOutcome, Topic, VERSION, encode_line,
};
use serde::de::DeserializeOwned;
use std::{error::Error, fmt, path::Path, time::Duration};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{UnixStream, unix::OwnedWriteHalf},
    sync::mpsc,
    task::JoinHandle,
    time::timeout,
};

pub const DEFAULT_TIMEOUT: Duration = Duration::from_secs(5);

pub struct Client {
    stream: OwnedWriteHalf,
    responses: mpsc::Receiver<Result<Response, ClientError>>,
    events: Option<mpsc::Receiver<Event>>,
    reader: JoinHandle<()>,
    next_id: u64,
    timeout: Duration,
}

impl Client {
    pub async fn connect(
        path: impl AsRef<Path>,
        timeout_duration: Duration,
    ) -> Result<Self, ClientError> {
        let stream = timeout(timeout_duration, UnixStream::connect(path))
            .await
            .map_err(|_| ClientError::Timeout)?
            .map_err(ClientError::Io)?;
        let (mut read, stream) = stream.into_split();
        let (response_tx, responses) = mpsc::channel(1);
        let (event_tx, events) = mpsc::channel(64);
        let reader = tokio::spawn(async move {
            loop {
                let parsed = read_line::<serde_json::Value>(&mut read).await;
                let result = match parsed {
                    Ok(value) if value.get("topic").is_some() => {
                        match serde_json::from_value::<Event>(value) {
                            Ok(event) if event.version == VERSION => {
                                if event_tx.try_send(event).is_err() {
                                    Err(ClientError::EventOverflow)
                                } else {
                                    continue;
                                }
                            }
                            Ok(event) => Err(ClientError::VersionMismatch(event.version)),
                            Err(_) => Err(ClientError::MalformedResponse),
                        }
                    }
                    Ok(value) => serde_json::from_value::<Response>(value)
                        .map_err(|_| ClientError::MalformedResponse)
                        .and_then(|response| {
                            if response.version != VERSION {
                                Err(ClientError::VersionMismatch(response.version))
                            } else {
                                Ok(response)
                            }
                        }),
                    Err(error) => Err(error),
                };
                let failed = result.is_err();
                if response_tx.try_send(result).is_err() || failed {
                    break;
                }
            }
        });
        let mut client = Self {
            stream,
            responses,
            events: Some(events),
            reader,
            next_id: 1,
            timeout: timeout_duration,
        };
        let response = client
            .request(Command::Hello {
                minimum_version: VERSION,
                maximum_version: VERSION,
            })
            .await?;
        match response.outcome {
            ResponseOutcome::Ok { .. } => Ok(client),
            ResponseOutcome::Error { error } => Err(ClientError::Remote {
                code: format!("{:?}", error.code),
                message: error.message,
            }),
        }
    }

    pub async fn request(&mut self, command: Command) -> Result<Response, ClientError> {
        let result = self.request_inner(command).await;
        if result.is_err() {
            self.reader.abort();
        }
        result
    }

    async fn request_inner(&mut self, command: Command) -> Result<Response, ClientError> {
        let id = self.next_id.to_string();
        self.next_id = self.next_id.saturating_add(1);
        let request = Request {
            version: VERSION,
            id: id.clone(),
            command,
        };
        let encoded = encode_line(&request).map_err(ClientError::Protocol)?;
        timeout(self.timeout, self.stream.write_all(&encoded))
            .await
            .map_err(|_| ClientError::Timeout)?
            .map_err(ClientError::Io)?;
        let response = match timeout(self.timeout, self.responses.recv()).await {
            Ok(Some(response)) => response?,
            Ok(None) => return Err(ClientError::Disconnected),
            Err(_) => {
                self.reader.abort();
                return Err(ClientError::Timeout);
            }
        };
        if response.version != VERSION {
            return Err(ClientError::VersionMismatch(response.version));
        }
        if response.id != id {
            return Err(ClientError::CorrelationMismatch);
        }
        Ok(response)
    }

    /// Subscribe once. A full event queue terminates the reader; reconnect and
    /// resubscribe to recover a fresh daemon snapshot instead of dropping events.
    pub async fn subscribe(
        &mut self,
        topics: Vec<Topic>,
    ) -> Result<(serde_json::Value, mpsc::Receiver<Event>), ClientError> {
        if self.events.is_none() {
            return Err(ClientError::AlreadySubscribed);
        }
        let response = self.request(Command::Subscribe { topics }).await?;
        match response.outcome {
            ResponseOutcome::Ok { result } => {
                Ok((result, self.events.take().expect("checked receiver")))
            }
            ResponseOutcome::Error { error } => Err(ClientError::Remote {
                code: format!("{:?}", error.code),
                message: error.message,
            }),
        }
    }
}

impl Drop for Client {
    fn drop(&mut self) {
        self.reader.abort();
    }
}

/// Restated at every panic invocation: erasure is local-only.
pub const PANIC_ERASE_WARNING: &str = "panic erase destroys the local master key and sealed \
state; it cannot retract messages, keys, or metadata already replicated to relays, peers, or \
backups";

/// Two-phase orchestration for destructive commands. The typed intent
/// (`ERASE`, or the handle echoed to `--confirm`) is checked locally; the
/// daemon-minted single-use token is then fetched out of band from the
/// daemon state directory and echoed back. Non-destructive commands pass
/// straight through.
pub async fn request_with_confirmation(
    client: &mut Client,
    command: Command,
) -> Result<Response, ClientError> {
    match command {
        Command::Panic { confirmation } => {
            if confirmation != "ERASE" {
                return Err(ClientError::ConfirmationRefused(
                    "panic requires --confirm ERASE".into(),
                ));
            }
            let issued = client.request(Command::RequestPanicConfirmation).await?;
            let ResponseOutcome::Ok { ref result } = issued.outcome else {
                return Ok(issued);
            };
            let token = read_confirmation_token(result)?;
            client
                .request(Command::Panic {
                    confirmation: token,
                })
                .await
        }
        Command::ClaimRegistryHandle {
            handle,
            confirmation,
        } => {
            if confirmation != handle {
                return Err(ClientError::ConfirmationRefused(
                    "claim-handle requires --confirm HANDLE to echo the handle exactly".into(),
                ));
            }
            let issued = client
                .request(Command::RequestRegistryClaimConfirmation {
                    handle: handle.clone(),
                })
                .await?;
            let ResponseOutcome::Ok { ref result } = issued.outcome else {
                return Ok(issued);
            };
            let token = read_confirmation_token(result)?;
            client
                .request(Command::ClaimRegistryHandle {
                    handle,
                    confirmation: token,
                })
                .await
        }
        other => client.request(other).await,
    }
}

fn read_confirmation_token(result: &serde_json::Value) -> Result<String, ClientError> {
    let path = result
        .get("token_path")
        .and_then(serde_json::Value::as_str)
        .ok_or_else(|| {
            ClientError::ConfirmationProtocol("daemon response lacked token_path".into())
        })?;
    // Token files are tens of bytes; a blocking read keeps the client free
    // of a tokio fs feature dependency.
    let mut file = std::fs::File::open(path)
        .map_err(|error| ClientError::ConfirmationProtocol(error.to_string()))?;
    if !file
        .metadata()
        .map_err(|error| ClientError::ConfirmationProtocol(error.to_string()))?
        .is_file()
    {
        return Err(ClientError::ConfirmationProtocol(
            "token is not a regular file".into(),
        ));
    }
    let mut token = String::new();
    std::io::Read::read_to_string(&mut std::io::Read::take(&mut file, 65), &mut token).map_err(
        |error| ClientError::ConfirmationProtocol(format!("token file unreadable: {error}")),
    )?;
    if token.len() != 64 || !token.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err(ClientError::ConfirmationProtocol(
            "token must be 32 hex-encoded bytes".into(),
        ));
    }
    Ok(token)
}

async fn read_line<T: DeserializeOwned>(
    stream: &mut (impl tokio::io::AsyncRead + Unpin),
) -> Result<T, ClientError> {
    let mut line = Vec::new();
    let mut byte = [0_u8; 1];
    loop {
        let count = stream.read(&mut byte).await.map_err(ClientError::Io)?;
        if count == 0 {
            return Err(ClientError::Disconnected);
        }
        if byte[0] == b'\n' {
            break;
        }
        if line.len() == MAX_LINE_BYTES {
            return Err(ClientError::LineTooLarge);
        }
        line.push(byte[0]);
    }
    serde_json::from_slice(&line).map_err(|_| ClientError::MalformedResponse)
}

#[derive(Debug)]
pub enum ClientError {
    Io(std::io::Error),
    Protocol(omachat_proto::ipc::IpcError),
    Timeout,
    EventOverflow,
    AlreadySubscribed,
    Disconnected,
    LineTooLarge,
    MalformedResponse,
    VersionMismatch(u16),
    CorrelationMismatch,
    Remote {
        code: String,
        message: String,
    },
    /// The locally typed intent (`--confirm` value) did not match; nothing
    /// was sent to the daemon.
    ConfirmationRefused(String),
    /// The daemon's confirmation-token response was malformed or the token
    /// file could not be read.
    ConfirmationProtocol(String),
}

impl fmt::Display for ClientError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io(error) => write!(formatter, "daemon connection failed: {error}"),
            Self::Protocol(error) => write!(formatter, "IPC request failed: {error}"),
            Self::EventOverflow => {
                formatter.write_str("daemon events exceeded client capacity; reconnect")
            }
            Self::AlreadySubscribed => formatter.write_str("client is already subscribed"),
            Self::Timeout => formatter.write_str("daemon request timed out"),
            Self::Disconnected => formatter.write_str("daemon disconnected"),
            Self::LineTooLarge => formatter.write_str("daemon response exceeds the size limit"),
            Self::MalformedResponse => formatter.write_str("daemon response is malformed"),
            Self::VersionMismatch(version) => {
                write!(formatter, "daemon uses incompatible IPC version {version}")
            }
            Self::CorrelationMismatch => formatter.write_str("daemon response ID does not match"),
            Self::Remote { code, message } => write!(formatter, "daemon error {code}: {message}"),
            Self::ConfirmationRefused(message) => write!(formatter, "refused: {message}"),
            Self::ConfirmationProtocol(message) => {
                write!(formatter, "confirmation protocol failed: {message}")
            }
        }
    }
}

impl Error for ClientError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Io(error) => Some(error),
            Self::Protocol(error) => Some(error),
            _ => None,
        }
    }
}
