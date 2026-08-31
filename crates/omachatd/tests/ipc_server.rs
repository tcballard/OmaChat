use omachat_proto::ipc::{
    Command, Event, Request, Response, ResponseOutcome, Topic, VERSION, encode_line,
};
use omachatd::{EventHub, IpcServer, RequestHandler, ServerError};
use serde_json::json;
use std::{future::Future, os::unix::fs::PermissionsExt, pin::Pin};
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
    task.await.expect("join").expect("server shutdown");
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
