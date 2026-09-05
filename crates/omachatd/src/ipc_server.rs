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
    os::unix::fs::{DirBuilderExt, FileTypeExt, OpenOptionsExt, PermissionsExt},
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

/// Publish the listening socket at its final path only once it is already
/// private. `UnixListener::bind` honours the process umask, so binding
/// directly and chmodding afterwards leaves a window in which another uid
/// can connect (finding #7) whenever the umask is permissive — a manual
/// launch without the packaged unit's `UMask=0077`, for instance.
///
/// Overriding the umask around `bind` would close that window but is not
/// safe here: umask is process-wide, so it would also strip bits from files
/// and directories created concurrently by other threads. Instead the
/// socket is bound inside a freshly created 0700 staging directory, where
/// no other uid can reach it, tightened to 0600 there, and then renamed
/// into place. `rename` is atomic and preserves the inode and its mode, so
/// the final path never exists in a world-accessible state and clients
/// connect to the same listening socket through it.
fn bind_private_socket(socket_path: &Path) -> Result<UnixListener, ServerError> {
    let parent = socket_path.parent().unwrap_or_else(|| Path::new("."));
    let file_name = socket_path
        .file_name()
        .ok_or(ServerError::OccupiedPath)?
        .to_string_lossy()
        .into_owned();
    let staging_directory = parent.join(format!(".{file_name}.staging"));
    // A stale staging directory can only be ours: the instance lock is held
    // by this process before bind runs. Recreation fails closed if another
    // process wins the race for the name.
    let _ = fs::remove_dir_all(&staging_directory);
    fs::DirBuilder::new()
        .mode(0o700)
        .create(&staging_directory)
        .map_err(ServerError::Io)?;
    // The requested 0700 is masked, never widened, by the process umask;
    // this restores the owner bits an exotic umask could have removed while
    // the directory was still empty.
    fs::set_permissions(&staging_directory, fs::Permissions::from_mode(0o700))
        .map_err(ServerError::Io)?;
    let staged_socket = staging_directory.join("socket");
    let bound = UnixListener::bind(&staged_socket);
    let published = bound.and_then(|listener| {
        fs::set_permissions(&staged_socket, fs::Permissions::from_mode(0o600))
            .and_then(|()| fs::rename(&staged_socket, socket_path))
            .map(|()| listener)
    });
    // The staging directory is transient on every path, including failure.
    let _ = fs::remove_dir_all(&staging_directory);
    published.map_err(ServerError::Io)
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
        let listener = bind_private_socket(&socket_path)?;
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
    use super::{bind_private_socket, peer_permitted};
    use std::os::unix::fs::PermissionsExt;
    use tempfile::tempdir;

    #[tokio::test]
    async fn the_published_socket_is_private_and_leaves_no_staging_directory() {
        let temporary = tempdir().expect("temporary directory");
        let socket = temporary.path().join("omachat.sock");
        let listener = bind_private_socket(&socket).expect("bind private socket");
        assert_eq!(
            std::fs::metadata(&socket)
                .expect("socket metadata")
                .permissions()
                .mode()
                & 0o777,
            0o600,
            "the socket is 0600 the moment it appears at its final path"
        );
        assert!(
            !temporary.path().join(".omachat.sock.staging").exists(),
            "the staging directory is removed after publication"
        );
        drop(listener);
    }

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
