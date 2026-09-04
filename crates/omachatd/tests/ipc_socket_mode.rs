//! Finding #7: the socket must never be reachable at its final path in a
//! world-accessible state. A permissive process umask simulates a manual
//! (non-systemd) launch without the packaged unit's UMask=0077, which is
//! exactly the case the old chmod-after-bind sequence left exposed.

use omachat_proto::ipc::{
    Command, Request, Response, ResponseOutcome, VERSION, encode_line, negotiate,
};
use omachatd::{EventHub, IpcServer, RequestHandler};
use rustix::fs::Mode;
use serde_json::{json, to_value};
use std::{future::Future, os::unix::fs::PermissionsExt, pin::Pin, time::Duration};
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
            match request.command {
                Command::Hello {
                    minimum_version,
                    maximum_version,
                } => match negotiate(minimum_version, maximum_version) {
                    Ok(result) => ResponseOutcome::Ok {
                        result: to_value(result).expect("hello result"),
                    },
                    Err(error) => ResponseOutcome::Error {
                        error: omachat_proto::ipc::ErrorBody {
                            code: omachat_proto::ipc::ErrorCode::VersionMismatch,
                            message: error.to_string(),
                        },
                    },
                },
                _ => ResponseOutcome::Ok { result: json!({}) },
            }
        })
    }
}

#[tokio::test]
async fn socket_is_published_private_even_under_a_permissive_umask() {
    // umask is process-wide; this integration-test binary holds a single
    // test, so nothing else in the process depends on it. The daemon must
    // not need this to be restrictive.
    let previous = rustix::process::umask(Mode::empty());
    let temporary = tempdir().expect("temporary directory");
    let socket = temporary.path().join("omachat.sock");
    let server = IpcServer::bind(&socket, Handler, EventHub::default()).expect("bind IPC server");
    let mode = std::fs::metadata(&socket)
        .expect("socket metadata")
        .permissions()
        .mode();
    assert_eq!(
        mode & 0o777,
        0o600,
        "socket must already be private when it appears at its final path"
    );
    assert!(
        !temporary.path().join(".omachat.sock.staging").exists(),
        "staging directory must not be left behind"
    );
    // The published path must still be the live listening socket: rename
    // keeps the inode, so clients connect through it normally.
    let (shutdown_sender, shutdown_receiver) = watch::channel(false);
    let task = tokio::spawn(server.run(shutdown_receiver));
    let stream = UnixStream::connect(&socket).await.expect("connect");
    let (reader, mut writer) = stream.into_split();
    let mut reader = BufReader::new(reader);
    writer
        .write_all(
            &encode_line(&Request {
                version: VERSION,
                id: "hello".into(),
                command: Command::Hello {
                    minimum_version: VERSION,
                    maximum_version: VERSION,
                },
            })
            .expect("encode hello"),
        )
        .await
        .expect("write hello");
    let mut line = String::new();
    tokio::time::timeout(Duration::from_secs(2), reader.read_line(&mut line))
        .await
        .expect("hello response timeout")
        .expect("read hello response");
    let response: Response = serde_json::from_str(&line).expect("hello response");
    assert!(matches!(response.outcome, ResponseOutcome::Ok { .. }));

    shutdown_sender.send(true).expect("shutdown");
    tokio::time::timeout(Duration::from_secs(2), task)
        .await
        .expect("server shutdown")
        .expect("server task")
        .expect("server result");
    let observed = rustix::process::umask(previous);
    assert_eq!(
        observed,
        Mode::empty(),
        "binding must not change the process umask"
    );
}
