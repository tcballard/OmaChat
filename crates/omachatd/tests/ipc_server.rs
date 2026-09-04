use omachat_proto::ipc::{
    Command, Event, Request, Response, ResponseOutcome, Topic, VERSION, encode_line,
};
use omachatd::{
    DaemonConfig, DaemonCore, EventHub, IpcServer, PanicState, RequestHandler, ServerError,
    StorageProviderConfig,
};
use serde_json::json;
use std::{
    future::Future,
    os::unix::fs::PermissionsExt,
    pin::Pin,
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, Ordering},
    },
    time::Duration,
};
use tempfile::tempdir;
use tokio::{
    io::{AsyncBufReadExt, AsyncWriteExt, BufReader},
    net::UnixStream,
    sync::watch,
};

struct Handler;

impl RequestHandler for Handler {
    fn handle(
        &self,
        request: Request,
    ) -> Pin<Box<dyn Future<Output = ResponseOutcome> + Send + '_>> {
        Box::pin(async move {
            ResponseOutcome::Ok {
                result: json!({"method": format!("{:?}", request.command)}),
            }
        })
    }
}

struct DelayedHandler {
    entered: Mutex<Option<tokio::sync::oneshot::Sender<()>>>,
    release: Arc<tokio::sync::Notify>,
}

impl RequestHandler for DelayedHandler {
    fn handle(
        &self,
        _request: Request,
    ) -> Pin<Box<dyn Future<Output = ResponseOutcome> + Send + '_>> {
        let entered = self.entered.lock().expect("entered mutex").take();
        let release = Arc::clone(&self.release);
        Box::pin(async move {
            if let Some(entered) = entered {
                entered.send(()).expect("signal active request");
            }
            release.notified().await;
            ResponseOutcome::Ok {
                result: json!({"completed": true}),
            }
        })
    }
}

struct StuckHandler {
    entered: Mutex<Option<tokio::sync::oneshot::Sender<()>>>,
    dropped: Arc<AtomicBool>,
}

struct DropSignal(Arc<AtomicBool>);

impl Drop for DropSignal {
    fn drop(&mut self) {
        self.0.store(true, Ordering::Release);
    }
}

impl RequestHandler for StuckHandler {
    fn handle(
        &self,
        _request: Request,
    ) -> Pin<Box<dyn Future<Output = ResponseOutcome> + Send + '_>> {
        let entered = self.entered.lock().expect("entered mutex").take();
        let dropped = Arc::clone(&self.dropped);
        Box::pin(async move {
            let _drop_signal = DropSignal(dropped);
            if let Some(entered) = entered {
                entered.send(()).expect("signal stuck request");
            }
            std::future::pending::<ResponseOutcome>().await
        })
    }
}

#[tokio::test]
async fn socket_is_private_and_hello_status_work() {
    let temporary = tempdir().expect("temporary directory");
    let socket = temporary.path().join("omachat.sock");
    let server = match IpcServer::bind(&socket, Handler, EventHub::default()) {
        Ok(server) => server,
        Err(ServerError::Io(error)) if error.kind() == std::io::ErrorKind::PermissionDenied => {
            // Some hermetic CI sandboxes prohibit AF_UNIX creation entirely.
            return;
        }
        Err(error) => panic!("bind: {error}"),
    };
    assert_eq!(
        std::fs::metadata(&socket)
            .expect("metadata")
            .permissions()
            .mode()
            & 0o777,
        0o600
    );
    let (shutdown_tx, shutdown_rx) = watch::channel(false);
    let task = tokio::spawn(server.run(shutdown_rx));

    let stream = UnixStream::connect(&socket).await.expect("connect");
    let (reader, mut writer) = stream.into_split();
    let mut reader = BufReader::new(reader);
    for request in [
        Request {
            version: VERSION,
            id: "hello".into(),
            command: Command::Hello {
                minimum_version: 1,
                maximum_version: 1,
            },
        },
        Request {
            version: VERSION,
            id: "status".into(),
            command: Command::Status,
        },
    ] {
        writer
            .write_all(&encode_line(&request).expect("encode"))
            .await
            .expect("write");
        let mut line = String::new();
        reader.read_line(&mut line).await.expect("read");
        let response: Response = serde_json::from_str(&line).expect("response");
        assert_eq!(response.id, request.id);
        assert!(matches!(response.outcome, ResponseOutcome::Ok { .. }));
    }

    shutdown_tx.send(true).expect("shutdown");
    tokio::time::timeout(Duration::from_secs(1), task)
        .await
        .expect("idle client shutdown")
        .expect("join")
        .expect("server shutdown");
}

#[tokio::test]
async fn shutdown_drains_an_active_request_response_before_closing_client() {
    let temporary = tempdir().expect("temporary directory");
    let socket = temporary.path().join("omachat.sock");
    let (entered_sender, entered_receiver) = tokio::sync::oneshot::channel();
    let release = Arc::new(tokio::sync::Notify::new());
    let server = match IpcServer::bind(
        &socket,
        DelayedHandler {
            entered: Mutex::new(Some(entered_sender)),
            release: Arc::clone(&release),
        },
        EventHub::default(),
    ) {
        Ok(server) => server,
        Err(ServerError::Io(error)) if error.kind() == std::io::ErrorKind::PermissionDenied => {
            return;
        }
        Err(error) => panic!("bind: {error}"),
    };
    let (shutdown_tx, shutdown_rx) = watch::channel(false);
    let server_task = tokio::spawn(server.run(shutdown_rx));
    let stream = UnixStream::connect(&socket).await.expect("connect");
    let (reader, mut writer) = stream.into_split();
    let mut reader = BufReader::new(reader);

    write_request(
        &mut writer,
        &mut reader,
        Request {
            version: VERSION,
            id: "hello".into(),
            command: Command::Hello {
                minimum_version: VERSION,
                maximum_version: VERSION,
            },
        },
    )
    .await;
    writer
        .write_all(
            &encode_line(&Request {
                version: VERSION,
                id: "slow".into(),
                command: Command::Status,
            })
            .expect("encode slow request"),
        )
        .await
        .expect("write slow request");
    entered_receiver.await.expect("request entered handler");
    shutdown_tx.send(true).expect("shutdown");
    tokio::task::yield_now().await;
    assert!(
        !server_task.is_finished(),
        "server must retain a client with an active request"
    );

    release.notify_one();
    tokio::time::timeout(Duration::from_secs(1), server_task)
        .await
        .expect("server drains active client")
        .expect("server task")
        .expect("server result");
    let response = read_response(&mut reader).await;
    assert_eq!(response.id, "slow");
    assert!(matches!(response.outcome, ResponseOutcome::Ok { .. }));
    assert_client_eof(&mut reader).await;
}

#[tokio::test]
async fn shutdown_aborts_a_handler_that_exceeds_the_drain_deadline() {
    let temporary = tempdir().expect("temporary directory");
    let socket = temporary.path().join("omachat.sock");
    let (entered_sender, entered_receiver) = tokio::sync::oneshot::channel();
    let dropped = Arc::new(AtomicBool::new(false));
    let server = match IpcServer::bind(
        &socket,
        StuckHandler {
            entered: Mutex::new(Some(entered_sender)),
            dropped: Arc::clone(&dropped),
        },
        EventHub::default(),
    ) {
        Ok(server) => server,
        Err(ServerError::Io(error)) if error.kind() == std::io::ErrorKind::PermissionDenied => {
            return;
        }
        Err(error) => panic!("bind: {error}"),
    };
    let (shutdown_tx, shutdown_rx) = watch::channel(false);
    let server_task = tokio::spawn(server.run(shutdown_rx));
    let stream = UnixStream::connect(&socket).await.expect("connect");
    let (reader, mut writer) = stream.into_split();
    let mut reader = BufReader::new(reader);
    write_request(
        &mut writer,
        &mut reader,
        Request {
            version: VERSION,
            id: "hello".into(),
            command: Command::Hello {
                minimum_version: VERSION,
                maximum_version: VERSION,
            },
        },
    )
    .await;
    writer
        .write_all(
            &encode_line(&Request {
                version: VERSION,
                id: "stuck".into(),
                command: Command::Status,
            })
            .expect("encode stuck request"),
        )
        .await
        .expect("write stuck request");
    entered_receiver.await.expect("stuck request entered");
    shutdown_tx.send(true).expect("shutdown");

    tokio::time::timeout(Duration::from_secs(5), server_task)
        .await
        .expect("drain deadline bounds shutdown")
        .expect("server task")
        .expect("server result");
    assert!(dropped.load(Ordering::Acquire), "stuck handler was aborted");
    assert_client_eof(&mut reader).await;
}

#[tokio::test]
async fn successful_panic_response_is_written_before_terminal_shutdown() {
    let Some((response, state)) = panic_response_during_terminal_shutdown(false).await else {
        return;
    };
    assert!(matches!(response.outcome, ResponseOutcome::Ok { .. }));
    assert_eq!(state, PanicState::CleanupComplete);
}

#[tokio::test]
async fn failed_panic_response_is_written_before_terminal_shutdown() {
    let Some((response, state)) = panic_response_during_terminal_shutdown(true).await else {
        return;
    };
    assert!(matches!(response.outcome, ResponseOutcome::Error { .. }));
    assert_eq!(state, PanicState::CleanupFailed);
}

#[test]
fn slow_subscriber_is_removed_at_the_bound() {
    let hub = EventHub::default();
    let _receiver = hub.subscribe();
    for sequence in 0..=64 {
        hub.publish(Event {
            version: VERSION,
            sequence,
            topic: Topic::Status,
            payload: json!({}),
        });
    }
    assert_eq!(hub.subscriber_count(), 0);
}

async fn panic_response_during_terminal_shutdown(
    fail_cleanup: bool,
) -> Option<(Response, PanicState)> {
    let temporary = tempdir().expect("temporary directory");
    let state_directory = temporary.path().join("state");
    let socket = temporary.path().join("omachat.sock");
    let events = EventHub::default();
    let core = DaemonCore::open(
        &state_directory,
        DaemonConfig {
            storage_provider: StorageProviderConfig::File,
            ..DaemonConfig::default()
        },
        events.clone(),
    )
    .await
    .expect("open core");
    if fail_cleanup {
        std::fs::remove_file(state_directory.join("master.key"))
            .expect("inject key cleanup failure");
    }
    let server = match IpcServer::bind(&socket, core.clone(), events) {
        Ok(server) => server,
        Err(ServerError::Io(error)) if error.kind() == std::io::ErrorKind::PermissionDenied => {
            return None;
        }
        Err(error) => panic!("bind: {error}"),
    };
    let (shutdown_tx, shutdown_rx) = watch::channel(false);
    let terminal_core = core.clone();
    let terminal_shutdown = tokio::spawn(async move {
        terminal_core.wait_for_panic_terminal().await;
        let _ = shutdown_tx.send(true);
    });
    let server_task = tokio::spawn(server.run(shutdown_rx));
    let stream = UnixStream::connect(&socket).await.expect("connect");
    let (reader, mut writer) = stream.into_split();
    let mut reader = BufReader::new(reader);

    write_request(
        &mut writer,
        &mut reader,
        Request {
            version: VERSION,
            id: "hello".into(),
            command: Command::Hello {
                minimum_version: VERSION,
                maximum_version: VERSION,
            },
        },
    )
    .await;
    writer
        .write_all(
            &encode_line(&Request {
                version: VERSION,
                id: "panic".into(),
                command: Command::Panic {
                    confirmation: "ERASE".into(),
                },
            })
            .expect("encode panic request"),
        )
        .await
        .expect("write panic request");
    tokio::time::timeout(Duration::from_secs(3), server_task)
        .await
        .expect("server drains panic response")
        .expect("server task")
        .expect("server result");
    let response = read_response(&mut reader).await;
    assert_eq!(response.id, "panic");
    terminal_shutdown.await.expect("terminal shutdown task");
    core.prepare_for_shutdown().await;
    assert_client_eof(&mut reader).await;
    Some((response, core.panic_state()))
}

async fn write_request(
    writer: &mut tokio::net::unix::OwnedWriteHalf,
    reader: &mut BufReader<tokio::net::unix::OwnedReadHalf>,
    request: Request,
) -> Response {
    writer
        .write_all(&encode_line(&request).expect("encode request"))
        .await
        .expect("write request");
    let response = read_response(reader).await;
    assert_eq!(response.id, request.id);
    response
}

async fn read_response(reader: &mut BufReader<tokio::net::unix::OwnedReadHalf>) -> Response {
    let mut line = String::new();
    tokio::time::timeout(Duration::from_secs(2), reader.read_line(&mut line))
        .await
        .expect("response timeout")
        .expect("read response");
    serde_json::from_str(&line).expect("response")
}

async fn assert_client_eof(reader: &mut BufReader<tokio::net::unix::OwnedReadHalf>) {
    let mut line = String::new();
    let count = tokio::time::timeout(Duration::from_secs(1), reader.read_line(&mut line))
        .await
        .expect("client close timeout")
        .expect("read client EOF");
    assert_eq!(count, 0, "server closed client after flushing response");
}

#[tokio::test]
async fn second_server_cannot_replace_a_live_ipc_endpoint() {
    let temporary = tempdir().expect("temporary directory");
    let socket = temporary.path().join("omachat.sock");
    let first = IpcServer::bind(&socket, Handler, EventHub::default()).expect("first bind");

    let second = IpcServer::bind(&socket, Handler, EventHub::default());
    assert!(matches!(second, Err(ServerError::AlreadyRunning)));
    assert!(socket.exists(), "the live endpoint remains addressable");

    drop(first);
    assert!(!socket.exists(), "the owner removes its endpoint on drop");
}
