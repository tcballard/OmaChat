use std::time::{Duration, SystemTime, UNIX_EPOCH};

use futures_util::{SinkExt, StreamExt};
use omachat_nostr::{
    auth::RelayAuthSigner,
    event::{EventLimits, SignedEvent},
    gift_wrap::{ChatRecipient, GiftWrapPersistence, create_chat_rumor, create_gift_wrap},
};
use omachat_proto::ipc::{Command, Request, ResponseOutcome, Topic, VERSION};
use omachatd::{DaemonConfig, DaemonCore, EventHub, RequestHandler, StorageProviderConfig};
use serde_json::{Value, json};
use tempfile::tempdir;
use tokio::{
    net::{TcpListener, TcpStream},
    time::timeout,
};
use tokio_tungstenite::{WebSocketStream, accept_async, tungstenite::Message};

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn configured_private_inbox_reaches_ipc_and_quiesces_before_panic_erasure() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let relay_url = format!("ws://{}", listener.local_addr().unwrap());
    let temporary = tempdir().unwrap();
    let events = EventHub::default();
    let mut event_receiver = events.subscribe();
    let core = DaemonCore::open(
        temporary.path(),
        DaemonConfig {
            storage_provider: StorageProviderConfig::File,
            dm_relays: vec![relay_url],
            ..DaemonConfig::default()
        },
        events,
    )
    .await
    .unwrap();
    let status = command(&core, Command::Status).await;
    assert_eq!(status["relay_count"], 0);
    assert_eq!(status["dm_relay_count"], 1);
    let recipient_public_key: [u8; 32] = hex::decode(
        status["nostr_public_key"]
            .as_str()
            .expect("device Nostr public key"),
    )
    .unwrap()
    .try_into()
    .unwrap();
    let now = unix_now();
    let sender_secret_key = [29_u8; 32];
    let sender_public_key = hex::encode(
        RelayAuthSigner::from_secret_key(sender_secret_key)
            .unwrap()
            .public_key(),
    );
    let rumor = create_chat_rumor(
        &sender_secret_key,
        now,
        &[ChatRecipient {
            public_key: recipient_public_key,
            relay_hint: None,
        }],
        "private daemon integration".to_owned(),
        None,
        None,
        &EventLimits::default(),
    )
    .unwrap();
    let gift_wrap = create_gift_wrap(
        &rumor,
        &sender_secret_key,
        &recipient_public_key,
        now,
        GiftWrapPersistence::Persistent,
        &EventLimits::default(),
    )
    .unwrap();
    let relay_task = tokio::spawn(serve_relay(listener, gift_wrap));

    let (inbound_sender, mut inbound_receiver) = tokio::sync::mpsc::channel(8);
    let service = core
        .start_dm_inbox(inbound_sender)
        .await
        .unwrap()
        .expect("configured inbox starts");
    let inbound_core = core.clone();
    let inbound_task = tokio::spawn(async move {
        while let Some(event) = inbound_receiver.recv().await {
            inbound_core.receive_dm_inbox_event(event);
        }
    });

    let event = timeout(Duration::from_secs(2), event_receiver.recv())
        .await
        .unwrap()
        .expect("private message reaches IPC event hub");
    assert_eq!(event.topic, Topic::Messages);
    assert_eq!(event.payload["text"], "private daemon integration");
    assert_eq!(
        event.payload["conversation"],
        format!("dm:{sender_public_key}")
    );
    assert_eq!(event.payload["delivery"], "received");

    let erased = command(
        &core,
        Command::Panic {
            confirmation: "ERASE".to_owned(),
        },
    )
    .await;
    assert_eq!(erased["erased"], true);
    assert!(!temporary.path().exists());
    timeout(Duration::from_secs(2), relay_task)
        .await
        .expect("panic waits for relay shutdown")
        .expect("relay task");
    service.shutdown().await.unwrap();
    timeout(Duration::from_secs(2), inbound_task)
        .await
        .expect("inbound task stops")
        .expect("inbound task");
}

#[tokio::test]
async fn invalid_private_relay_fails_before_state_creation() {
    let temporary = tempdir().unwrap();
    let result = DaemonCore::open(
        temporary.path(),
        DaemonConfig {
            storage_provider: StorageProviderConfig::File,
            dm_relays: vec!["https://not-a-websocket.example".to_owned()],
            ..DaemonConfig::default()
        },
        EventHub::default(),
    )
    .await;
    assert!(result.is_err());
    assert!(!temporary.path().join("storage-mode").exists());
}

async fn command(core: &DaemonCore, command: Command) -> Value {
    match core
        .handle(Request {
            version: VERSION,
            id: "dm-inbox-enable-test".to_owned(),
            command,
        })
        .await
    {
        ResponseOutcome::Ok { result } => result,
        ResponseOutcome::Error { error } => panic!("daemon error: {}", error.message),
    }
}

async fn serve_relay(listener: TcpListener, gift_wrap: SignedEvent) {
    let (stream, _) = listener.accept().await.unwrap();
    let mut websocket = accept_async(stream).await.unwrap();
    websocket
        .send(Message::Text(
            json!(["AUTH", "daemon-enable-test"]).to_string().into(),
        ))
        .await
        .unwrap();
    let auth_frame = next_json(&mut websocket).await;
    assert_eq!(auth_frame[0], "AUTH");
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
    assert_eq!(request[2]["kinds"], json!([1059]));
    assert_eq!(request[2]["#p"], json!([auth_event.pubkey]));
    websocket
        .send(Message::Text(
            json!(["EVENT", request[1], gift_wrap]).to_string().into(),
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
