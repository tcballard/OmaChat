use std::time::{Duration, SystemTime, UNIX_EPOCH};

use futures_util::{SinkExt, StreamExt};
use omachat_nostr::{
    auth::RelayAuthSigner,
    event::{EventLimits, SignedEvent},
};
use omachat_proto::ipc::{Command, Request, ResponseOutcome, VERSION};
use omachatd::{DaemonConfig, DaemonCore, EventHub, RequestHandler, StorageProviderConfig};
use serde_json::{Value, json};
use tempfile::tempdir;
use tokio::{
    net::{TcpListener, TcpStream},
    time::{sleep, timeout},
};
use tokio_tungstenite::{WebSocketStream, accept_async, tungstenite::Message};

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn reauthentication_drains_the_exact_queued_nip17_event() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let relay_url = format!("ws://{}", listener.local_addr().unwrap());
    let relay_task = tokio::spawn(serve_two_connections(listener));
    let temporary = tempdir().unwrap();
    let core = DaemonCore::open(
        temporary.path(),
        DaemonConfig {
            storage_provider: StorageProviderConfig::File,
            dm_relays: vec![relay_url],
            ..DaemonConfig::default()
        },
        EventHub::default(),
    )
    .await
    .unwrap();
    let recipient_public_key = hex::encode(
        RelayAuthSigner::from_secret_key([47_u8; 32])
            .unwrap()
            .public_key(),
    );
    let (inbound_sender, _inbound_receiver) = tokio::sync::mpsc::channel(8);
    let (ready_sender, mut ready_receiver) = tokio::sync::mpsc::channel(1);
    let service = core
        .start_dm_inbox_with_ready(inbound_sender, ready_sender)
        .await
        .unwrap()
        .expect("configured inbox starts");
    let drain_core = core.clone();
    let drain_task = tokio::spawn(async move {
        while ready_receiver.recv().await.is_some() {
            drain_core.drain_outbox().await;
        }
    });

    let sent = command(
        &core,
        Command::Send {
            conversation: recipient_public_key,
            text: "retry exact signed event".to_owned(),
        },
    )
    .await;
    assert_eq!(sent["delivery"], "queued");
    assert_eq!(command(&core, Command::Status).await["outbox_pending"], 1);

    timeout(Duration::from_secs(4), async {
        loop {
            if command(&core, Command::Status).await["outbox_pending"] == 0 {
                break;
            }
            sleep(Duration::from_millis(20)).await;
        }
    })
    .await
    .expect("re-authentication triggers queued delivery");

    core.prepare_for_shutdown().await;
    service.shutdown().await.unwrap();
    let (first_id, second_id) = timeout(Duration::from_secs(2), relay_task)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(first_id, sent["id"]);
    assert_eq!(second_id, first_id);
    timeout(Duration::from_secs(2), drain_task)
        .await
        .unwrap()
        .unwrap();
}

async fn command(core: &DaemonCore, command: Command) -> Value {
    match core
        .handle(Request {
            version: VERSION,
            id: "reconnect-drain-test".to_owned(),
            command,
        })
        .await
    {
        ResponseOutcome::Ok { result } => result,
        ResponseOutcome::Error { error } => panic!("daemon error: {}", error.message),
    }
}

async fn serve_two_connections(listener: TcpListener) -> (String, String) {
    let first_id = {
        let mut websocket = authenticated_connection(&listener).await;
        let publish = next_json(&mut websocket).await;
        assert_eq!(publish[0], "EVENT");
        let event: SignedEvent = serde_json::from_value(publish[1].clone()).unwrap();
        websocket
            .send(Message::Text(
                json!(["OK", event.id, false, "temporary failure"])
                    .to_string()
                    .into(),
            ))
            .await
            .unwrap();
        event.id
    };

    let second_id = {
        let mut websocket = authenticated_connection(&listener).await;
        let publish = next_json(&mut websocket).await;
        assert_eq!(publish[0], "EVENT");
        let event: SignedEvent = serde_json::from_value(publish[1].clone()).unwrap();
        websocket
            .send(Message::Text(
                json!(["OK", event.id, true, "stored"]).to_string().into(),
            ))
            .await
            .unwrap();
        while let Some(message) = websocket.next().await {
            match message {
                Ok(Message::Ping(payload)) => {
                    websocket.send(Message::Pong(payload)).await.unwrap();
                }
                Ok(Message::Close(_)) | Err(_) => break,
                Ok(_) => {}
            }
        }
        event.id
    };
    (first_id, second_id)
}

async fn authenticated_connection(listener: &TcpListener) -> WebSocketStream<TcpStream> {
    let (stream, _) = listener.accept().await.unwrap();
    let mut websocket = accept_async(stream).await.unwrap();
    websocket
        .send(Message::Text(
            json!(["AUTH", "daemon-reconnect-drain-test"])
                .to_string()
                .into(),
        ))
        .await
        .unwrap();
    let auth_frame = next_json(&mut websocket).await;
    assert_eq!(auth_frame[0], "AUTH", "REQ arrived before reconnect AUTH");
    let auth_event: SignedEvent = serde_json::from_value(auth_frame[1].clone()).unwrap();
    auth_event
        .verify(unix_now() + 1, &EventLimits::default())
        .unwrap();
    websocket
        .send(Message::Text(
            json!(["OK", auth_event.id, true, ""]).to_string().into(),
        ))
        .await
        .unwrap();
    let request = next_json(&mut websocket).await;
    assert_eq!(request[0], "REQ");
    websocket
}

async fn next_json(websocket: &mut WebSocketStream<TcpStream>) -> Value {
    loop {
        match websocket.next().await {
            Some(Ok(Message::Text(text))) => return serde_json::from_str(&text).unwrap(),
            Some(Ok(Message::Ping(payload))) => {
                websocket.send(Message::Pong(payload)).await.unwrap();
            }
            Some(Ok(Message::Close(frame))) => {
                panic!("relay closed before expected frame: {frame:?}");
            }
            Some(Ok(_)) => {}
            Some(Err(error)) => panic!("relay WebSocket failed: {error}"),
            None => panic!("relay WebSocket ended before expected frame"),
        }
    }
}

fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs()
}
