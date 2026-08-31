//! Bounded IPC client used by the scripting command.

use omachat_proto::ipc::{
    Command, MAX_LINE_BYTES, Request, Response, ResponseOutcome, VERSION, encode_line,
};
use serde::de::DeserializeOwned;
use std::{error::Error, fmt, path::Path, time::Duration};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::UnixStream,
    time::timeout,
};

pub const DEFAULT_TIMEOUT: Duration = Duration::from_secs(5);

pub struct Client {
    stream: UnixStream,
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
        let mut client = Self {
            stream,
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
        let response: Response = timeout(self.timeout, read_line(&mut self.stream))
            .await
            .map_err(|_| ClientError::Timeout)??;
        if response.version != VERSION {
            return Err(ClientError::VersionMismatch(response.version));
        }
        if response.id != id {
            return Err(ClientError::CorrelationMismatch);
        }
        Ok(response)
    }
}

async fn read_line<T: DeserializeOwned>(stream: &mut UnixStream) -> Result<T, ClientError> {
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
    Disconnected,
    LineTooLarge,
    MalformedResponse,
    VersionMismatch(u16),
    CorrelationMismatch,
    Remote { code: String, message: String },
}

impl fmt::Display for ClientError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io(error) => write!(formatter, "daemon connection failed: {error}"),
            Self::Protocol(error) => write!(formatter, "IPC request failed: {error}"),
            Self::Timeout => formatter.write_str("daemon request timed out"),
            Self::Disconnected => formatter.write_str("daemon disconnected"),
            Self::LineTooLarge => formatter.write_str("daemon response exceeds the size limit"),
            Self::MalformedResponse => formatter.write_str("daemon response is malformed"),
            Self::VersionMismatch(version) => {
                write!(formatter, "daemon uses incompatible IPC version {version}")
            }
            Self::CorrelationMismatch => formatter.write_str("daemon response ID does not match"),
            Self::Remote { code, message } => write!(formatter, "daemon error {code}: {message}"),
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
