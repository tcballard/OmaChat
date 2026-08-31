use omachat_proto::ipc::{
    Command, ErrorBody, ErrorCode, Event, IpcError, Request, RequestDecoder, Response,
    ResponseOutcome, VERSION, encode_line, negotiate,
};
use serde_json::to_value;
use std::{
    error::Error,
    fmt, fs,
    future::Future,
    os::unix::fs::{FileTypeExt, PermissionsExt},
    path::{Path, PathBuf},
    pin::Pin,
    sync::{Arc, Mutex},
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{UnixListener, UnixStream},
    sync::{mpsc, watch},
};

const EVENT_QUEUE_CAPACITY: usize = 64;
const CLIENT_READ_CHUNK: usize = 8 * 1024;

pub trait RequestHandler: Send + Sync + 'static {
    fn handle(
        &self,
        request: Request,
    ) -> Pin<Box<dyn Future<Output = ResponseOutcome> + Send + '_>>;
}
#[derive(Clone, Default)]
pub struct EventHub {
    subscribers: Arc<Mutex<Vec<mpsc::Sender<Event>>>>,
}

impl EventHub {
    #[must_use]
    pub fn subscribe(&self) -> mpsc::Receiver<Event> {
        let (sender, receiver) = mpsc::channel(EVENT_QUEUE_CAPACITY);
        self.subscribers
            .lock()
            .expect("event subscriber mutex poisoned")
            .push(sender);
        receiver
    }

    /// Publish without waiting for a client. Full clients are disconnected by
    /// dropping their sole sender, bounding daemon memory and latency.
    pub fn publish(&self, event: Event) {
        self.subscribers
            .lock()
            .expect("event subscriber mutex poisoned")
            .retain(|sender| match sender.try_send(event.clone()) {
                Ok(()) => true,
                Err(mpsc::error::TrySendError::Full(_) | mpsc::error::TrySendError::Closed(_)) => {
                    false
                }
            });
    }

    #[must_use]
    pub fn subscriber_count(&self) -> usize {
        self.subscribers
            .lock()
            .expect("event subscriber mutex poisoned")
            .len()
    }
}

pub struct IpcServer<H> {
    listener: UnixListener,
    socket_path: PathBuf,
    handler: Arc<H>,
    events: EventHub,
}

impl<H: RequestHandler> IpcServer<H> {
    pub fn bind(
        socket_path: impl AsRef<Path>,
        handler: H,
        events: EventHub,
    ) -> Result<Self, ServerError> {
        let socket_path = socket_path.as_ref().to_owned();
        if socket_path.exists() {
            let metadata = fs::symlink_metadata(&socket_path).map_err(ServerError::Io)?;
            if !metadata.file_type().is_socket() {
                return Err(ServerError::OccupiedPath);
            }
            fs::remove_file(&socket_path).map_err(ServerError::Io)?;
        }
        let listener = UnixListener::bind(&socket_path).map_err(ServerError::Io)?;
        fs::set_permissions(&socket_path, fs::Permissions::from_mode(0o600))
            .map_err(ServerError::Io)?;
        Ok(Self {
            listener,
            socket_path,
            handler: Arc::new(handler),
            events,
        })
    }

    pub async fn run(self, mut shutdown: watch::Receiver<bool>) -> Result<(), ServerError> {
        loop {
            tokio::select! {
                changed = shutdown.changed() => {
                    if changed.is_err() || *shutdown.borrow() {
                        break;
                    }
                }
                accepted = self.listener.accept() => {
                    let (stream, _) = accepted.map_err(ServerError::Io)?;
                    let handler = Arc::clone(&self.handler);
                    let events = self.events.clone();
                    tokio::spawn(async move {
                        let _ = serve_client(stream, handler, events).await;
                    });
                }
            }
        }
        Ok(())
    }

    #[must_use]
    pub fn socket_path(&self) -> &Path {
        &self.socket_path
    }
}

impl<H> Drop for IpcServer<H> {
    fn drop(&mut self) {
        let _ = fs::remove_file(&self.socket_path);
    }
}

async fn serve_client<H: RequestHandler>(
    mut stream: UnixStream,
    handler: Arc<H>,
    events: EventHub,
) -> Result<(), ServerError> {
    let mut decoder = RequestDecoder::default();
    let mut read_buffer = [0_u8; CLIENT_READ_CHUNK];
    let mut negotiated = false;
    let mut subscribed = false;
    let mut event_receiver = events.subscribe();

    loop {
        tokio::select! {
            read = stream.read(&mut read_buffer) => {
                let count = read.map_err(ServerError::Io)?;
                if count == 0 {
                    decoder.finish().map_err(ServerError::Protocol)?;
                    return Ok(());
                }
                let requests = decoder
                    .push(&read_buffer[..count])
                    .map_err(ServerError::Protocol)?;
                for request in requests {
                    let id = request.id.clone();
                    let outcome = match &request.command {
                        Command::Hello { minimum_version, maximum_version } => {
                            match negotiate(*minimum_version, *maximum_version) {
                                Ok(result) => {
                                    negotiated = true;
                                    ResponseOutcome::Ok {
                                        result: to_value(result).expect("hello result serializes"),
                                    }
                                }
                                Err(error) => protocol_error(ErrorCode::VersionMismatch, &error),
                            }
                        }
                        _ if !negotiated => protocol_error(
                            ErrorCode::VersionMismatch,
                            &IpcError::VersionMismatch {
                                minimum: 0,
                                maximum: 0,
                                supported: VERSION,
                            },
                        ),
                        Command::Subscribe { .. } => {
                            subscribed = true;
                            handler.handle(request).await
                        }
                        _ => handler.handle(request).await,
                    };
                    let response = Response { version: VERSION, id, outcome };
                    stream
                        .write_all(&encode_line(&response).map_err(ServerError::Protocol)?)
                        .await
                        .map_err(ServerError::Io)?;
                    if !negotiated {
                        return Ok(());
                    }
                }
            }
            event = event_receiver.recv(), if subscribed => {
                let Some(event) = event else { return Ok(()) };
                stream
                    .write_all(&encode_line(&event).map_err(ServerError::Protocol)?)
                    .await
                    .map_err(ServerError::Io)?;
            }
        }
    }
}

fn protocol_error(code: ErrorCode, error: &impl fmt::Display) -> ResponseOutcome {
    ResponseOutcome::Error {
        error: ErrorBody {
            code,
            message: error.to_string(),
        },
    }
}

#[derive(Debug)]
pub enum ServerError {
    Io(std::io::Error),
    Protocol(IpcError),
    OccupiedPath,
}

impl fmt::Display for ServerError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io(error) => write!(formatter, "IPC I/O failed: {error}"),
            Self::Protocol(error) => write!(formatter, "IPC protocol failed: {error}"),
            Self::OccupiedPath => formatter.write_str("IPC path exists and is not a socket"),
        }
    }
}

impl Error for ServerError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Io(error) => Some(error),
            Self::Protocol(error) => Some(error),
            Self::OccupiedPath => None,
        }
    }
}
