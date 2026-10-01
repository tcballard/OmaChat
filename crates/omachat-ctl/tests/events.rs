use omachat_ctl::{Client, ClientError, DEFAULT_TIMEOUT};
use omachat_proto::ipc::{
    Command, Event, RequestDecoder, Response, ResponseOutcome, Topic, VERSION, encode_line,
};
use serde_json::json;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::UnixListener,
};

async fn peer(listener: UnixListener, bad_version: bool, flood: bool) {
    let (mut socket, _) = listener.accept().await.unwrap();
    let mut decoder = RequestDecoder::default();
    let mut bytes = [0; 4096];
    loop {
        let count = match socket.read(&mut bytes).await {
            Ok(count) => count,
            Err(error) if error.kind() == std::io::ErrorKind::ConnectionReset => return,
            Err(error) => panic!("read: {error}"),
        };
        if count == 0 {
            return;
        }
        for request in decoder.push(&bytes[..count]).unwrap() {
            if matches!(request.command, Command::Subscribe { .. } | Command::Status) {
                for sequence in 0..if flood { 65 } else { 1 } {
                    let event = Event {
                        version: if bad_version { VERSION + 1 } else { VERSION },
                        sequence,
                        topic: Topic::Messages,
                        payload: json!({"text": "interleaved"}),
                    };
                    if socket
                        .write_all(&encode_line(&event).unwrap())
                        .await
                        .is_err()
                    {
                        return;
                    }
                }
            }
            let response = Response {
                version: VERSION,
                id: request.id,
                outcome: ResponseOutcome::Ok { result: json!({}) },
            };
            if socket
                .write_all(&encode_line(&response).unwrap())
                .await
                .is_err()
            {
                return;
            }
            if matches!(request.command, Command::Status) {
                return;
            }
        }
    }
}

#[tokio::test]
async fn events_before_responses_do_not_break_correlation() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("ipc");
    let task = tokio::spawn(peer(UnixListener::bind(&path).unwrap(), false, false));
    let mut client = Client::connect(path, DEFAULT_TIMEOUT).await.unwrap();
    let (_, mut events) = client.subscribe(vec![Topic::Messages]).await.unwrap();
    assert_eq!(events.recv().await.unwrap().payload["text"], "interleaved");
    assert!(client.request(Command::Status).await.is_ok());
    assert_eq!(events.recv().await.unwrap().topic, Topic::Messages);
    task.await.unwrap();
    assert!(events.recv().await.is_none());
}

#[tokio::test]
async fn incompatible_event_fails_closed() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("ipc");
    let task = tokio::spawn(peer(UnixListener::bind(&path).unwrap(), true, false));
    let mut client = Client::connect(path, DEFAULT_TIMEOUT).await.unwrap();
    assert!(matches!(
        client.subscribe(vec![Topic::Messages]).await,
        Err(ClientError::VersionMismatch(_))
    ));
    drop(client);
    task.await.unwrap();
}

#[tokio::test]
async fn stalled_event_consumer_disconnects_at_the_bound() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("ipc");
    let task = tokio::spawn(peer(UnixListener::bind(&path).unwrap(), false, true));
    let mut client = Client::connect(path, DEFAULT_TIMEOUT).await.unwrap();
    assert!(matches!(
        client.subscribe(vec![Topic::Messages]).await,
        Err(ClientError::EventOverflow)
    ));
    drop(client);
    task.await.unwrap();
}
