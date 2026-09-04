use omachat_proto::ipc::{
    Command, ErrorBody, ErrorCode, Event, IpcError, Request, RequestDecoder, Response,
    ResponseOutcome, VERSION, encode_line, negotiate,
};
use serde_json::to_value;
use std::{
    error::Error,
    fmt, fs,
    fs::{File, OpenOptions},
    future::Future,
    os::unix::fs::{FileTypeExt, OpenOptionsExt, PermissionsExt},
    path::{Path, PathBuf},
    pin::Pin,
    sync::{Arc, Mutex},
    time::Duration,
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{UnixListener, UnixStream},
    sync::{mpsc, watch},
    task::JoinSet,
};

const EVENT_QUEUE_CAPACITY: usize = 64;
const CLIENT_READ_CHUNK: usize = 8 * 1024;
const CLIENT_DRAIN_TIMEOUT: Duration = Duration::from_secs(2);

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
    lock_path: PathBuf,
    _instance_lock: File,
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
        let lock_path = socket_path.with_extension("lock");
        let instance_lock = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .mode(0o600)
            .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW)
            .open(&lock_path)
            .map_err(ServerError::Io)?;
        instance_lock.try_lock().map_err(|error| match error {
            fs::TryLockError::WouldBlock => ServerError::AlreadyRunning,
            fs::TryLockError::Error(error) => ServerError::Io(error),
        })?;
        fs::set_permissions(&lock_path, fs::Permissions::from_mode(0o600))
            .map_err(ServerError::Io)?;
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
            lock_path,
            _instance_lock: instance_lock,
            handler: Arc::new(handler),
            events,
        })
    }

    pub async fn run(self, mut shutdown: watch::Receiver<bool>) -> Result<(), ServerError> {
        let mut clients = JoinSet::new();
        let mut terminal_error = None;
        let (client_shutdown_sender, client_shutdown) = watch::channel(false);
        let daemon_euid = rustix::process::geteuid().as_raw();
        loop {
            if *shutdown.borrow() {
                break;
            }
            tokio::select! {
                biased;
                changed = shutdown.changed() => {
                    if changed.is_err() || *shutdown.borrow() {
                        break;
                    }
                }
                accepted = self.listener.accept() => {
                    let (stream, _) = match accepted {
                        Ok(accepted) => accepted,
                        Err(error) => {
                            terminal_error = Some(ServerError::Io(error));
                            break;
                        }
                    };
                    match stream.peer_cred() {
                        Ok(credentials) if peer_permitted(credentials.uid(), daemon_euid) => {}
                        // Fail closed: a foreign or unreadable peer gets no
                        // protocol bytes at all, not even an error frame.
                        Ok(_) | Err(_) => continue,
                    }
                    let handler = Arc::clone(&self.handler);
                    let events = self.events.clone();
                    let client_shutdown = client_shutdown.clone();
                    clients.spawn(async move {
                        serve_client(stream, handler, events, client_shutdown).await
                    });
                }
                completed = clients.join_next(), if !clients.is_empty() => {
                    let _ = completed;
                }
            }
        }
        // Prevent new connections through the filesystem path while existing
        // clients receive their local shutdown signal and drain.
        let _ = fs::remove_file(&self.socket_path);
        client_shutdown_sender.send_replace(true);
        // Idle clients observe the shutdown receiver and exit immediately.
        // A client already inside RequestHandler::handle is intentionally not
        // cancelled: it writes that response, observes shutdown at the next
        // boundary, and then exits. This is what keeps a panic result from
        // being lost during runtime teardown. The deadline prevents a wedged
        // handler or non-reading client from blocking process shutdown.
        if tokio::time::timeout(CLIENT_DRAIN_TIMEOUT, async {
            while clients.join_next().await.is_some() {}
        })
        .await
        .is_err()
        {
            clients.abort_all();
            while clients.join_next().await.is_some() {}
        }
        terminal_error.map_or(Ok(()), Err)
    }

    #[must_use]
    pub fn socket_path(&self) -> &Path {
        &self.socket_path
    }
}

impl<H> Drop for IpcServer<H> {
    fn drop(&mut self) {
        let _ = fs::remove_file(&self.socket_path);
        let _ = fs::remove_file(&self.lock_path);
    }
}

async fn serve_client<H: RequestHandler>(
    mut stream: UnixStream,
    handler: Arc<H>,
    events: EventHub,
    mut shutdown: watch::Receiver<bool>,
) -> Result<(), ServerError> {
    let mut decoder = RequestDecoder::default();
    let mut read_buffer = [0_u8; CLIENT_READ_CHUNK];
    let mut negotiated = false;
    let mut subscribed = false;
    let mut event_receiver = events.subscribe();

    loop {
        if *shutdown.borrow() {
            return Ok(());
        }
        tokio::select! {
            biased;
            changed = shutdown.changed() => {
                if changed.is_err() || *shutdown.borrow() {
                    return Ok(());
                }
            }
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
                    if !negotiated || *shutdown.borrow() {
                        return Ok(());
                    }
                }
            }
            event = event_receiver.recv(), if subscribed => {
                let Some(event) = event else { return Ok(()) };
                let encoded = encode_line(&event).map_err(ServerError::Protocol)?;
                tokio::select! {
                    biased;
                    changed = shutdown.changed() => {
                        if changed.is_err() || *shutdown.borrow() {
                            return Ok(());
                        }
                    }
                    result = stream.write_all(&encoded) => {
                        result.map_err(ServerError::Io)?;
                    }
                }
            }
        }
    }
}

/// SO_PEERCRED authorization: only the daemon's own effective uid may speak
/// the protocol. The uid in `UCred` is fixed by the kernel at connect()
/// time and cannot be spoofed by the client. The pid is deliberately not
/// consulted (pid reuse races). This is defense in depth, not a hard
/// boundary: a same-uid process can ptrace the daemon — see SECURITY.md.
fn peer_permitted(peer_uid: u32, daemon_euid: u32) -> bool {
    peer_uid == daemon_euid
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
    AlreadyRunning,
}

impl fmt::Display for ServerError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io(error) => write!(formatter, "IPC I/O failed: {error}"),
            Self::Protocol(error) => write!(formatter, "IPC protocol failed: {error}"),
            Self::OccupiedPath => formatter.write_str("IPC path exists and is not a socket"),
            Self::AlreadyRunning => formatter.write_str("another daemon owns the IPC endpoint"),
        }
    }
}

impl Error for ServerError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Io(error) => Some(error),
            Self::Protocol(error) => Some(error),
            Self::OccupiedPath | Self::AlreadyRunning => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::peer_permitted;

    #[test]
    fn only_the_daemon_uid_is_permitted() {
        assert!(peer_permitted(1000, 1000));
        assert!(!peer_permitted(1001, 1000));
        // Root is not exempted: a root peer can bypass any socket check
        // through other means, so accepting it here would only widen the
        // daemon's accepted-input surface without adding capability.
        assert!(!peer_permitted(0, 1000));
        assert!(peer_permitted(0, 0));
    }
}
