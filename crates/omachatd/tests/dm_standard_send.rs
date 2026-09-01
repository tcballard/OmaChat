use std::time::{Duration, SystemTime, UNIX_EPOCH};

use futures_util::{SinkExt, StreamExt};
use omachat_nostr::{
    auth::RelayAuthSigner,
    event::{EventLimits, SignedEvent},
    gift_wrap::{CHAT_MESSAGE_KIND, open_gift_wrap},
};
use omachat_proto::ipc::{Command, Request, ResponseOutcome, VERSION};
use omachatd::{DaemonConfig, DaemonCore, EventHub, RequestHandler, StorageProviderConfig};
use serde_json::{Value, json};
use tempfile::tempdir;
use tokio::{
    net::{TcpListener, TcpStream},
    time::timeout,
};
use tokio_tungstenite::{WebSocketStream, accept_async, tungstenite::Message};

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn daemon_send_publishes_restart_safe_standard_nip17_authorship() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let relay_url = format!("ws://{}", listener.local_addr().unwrap());
    let relay_task = tokio::spawn(serve_relay(listener));
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
    let status = command(&core, Command::Status).await;
    let sender_public_key = status["nostr_public_key"].as_str().unwrap().to_owned();
    let recipient_secret_key = [43_u8; 32];
    let recipient_public_key = *RelayAuthSigner::from_secret_key(recipient_secret_key)
        .unwrap()
        .public_key();
    let recipient_public_key_hex = hex::encode(recipient_public_key);
    let (inbound_sender, _inbound_receiver) = tokio::sync::mpsc::channel(8);
    let service = core
        .start_dm_inbox(inbound_sender)
        .await
        .unwrap()
        .expect("configured private relay starts");

    let sent = command(
        &core,
        Command::Send {
            conversation: recipient_public_key_hex,
            text: "standard daemon message".to_owned(),
        },
    )
    .await;
    assert_eq!(sent["delivery"], "stored");
    assert_eq!(command(&core, Command::Status).await["outbox_pending"], 0);

    core.prepare_for_shutdown().await;
    service.shutdown().await.unwrap();
    let published = timeout(Duration::from_secs(2), relay_task)
        .await
        .unwrap()
        .unwrap();
    let opened = open_gift_wrap(
        &published,
        &recipient_secret_key,
        unix_now() + 1,
        &EventLimits::default(),
    )
    .unwrap();
    assert_eq!(opened.rumor.kind, CHAT_MESSAGE_KIND);
    assert_eq!(opened.rumor.pubkey, sender_public_key);
    assert_eq!(opened.rumor.content, "standard daemon message");
}

async fn command(core: &DaemonCore, command: Command) -> Value {
    match core
        .handle(Request {
            version: VERSION,
            id: "standard-send-test".to_owned(),
            command,
        })
        .await
    {
        ResponseOutcome::Ok { result } => result,
        ResponseOutcome::Error { error } => panic!("daemon error: {}", error.message),
    }
}

async fn serve_relay(listener: TcpListener) -> SignedEvent {
    let (inbound_stream, _) = listener.accept().await.unwrap();
    let inbound = tokio::spawn(async move {
        let mut websocket = accept_async(inbound_stream).await.unwrap();
        authenticate(&mut websocket, "daemon-standard-inbox-test").await;
        let request = next_json(&mut websocket).await;
        assert_eq!(request[0], "REQ");
        assert_eq!(request[2]["kinds"], json!([1059]));
        wait_for_close(&mut websocket).await;
    });

    let (outbound_stream, _) = listener.accept().await.unwrap();
    let mut websocket = accept_async(outbound_stream).await.unwrap();
    authenticate(&mut websocket, "daemon-standard-send-test").await;
    let publish = next_json(&mut websocket).await;
    assert_eq!(publish[0], "EVENT");
    let event: SignedEvent = serde_json::from_value(publish[1].clone()).unwrap();
    event
        .verify(unix_now() + 1, &EventLimits::default())
        .unwrap();
    websocket
        .send(Message::Text(
            json!(["OK", event.id, true, "stored"]).to_string().into(),
        ))
        .await
        .unwrap();
    wait_for_close(&mut websocket).await;
    inbound.await.unwrap();
    event
}

async fn authenticate(websocket: &mut WebSocketStream<TcpStream>, challenge: &str) {
    websocket
        .send(Message::Text(json!(["AUTH", challenge]).to_string().into()))
        .await
        .unwrap();
    let auth_frame = next_json(websocket).await;
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
}

async fn wait_for_close(websocket: &mut WebSocketStream<TcpStream>) {
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
