use std::time::{Duration, SystemTime, UNIX_EPOCH};

use futures_util::{SinkExt, StreamExt};
use omachat_nostr::{
    discovery::NIP17_DM_RELAY_LIST_KIND,
    dm_relay_cache::CacheMutation,
    event::{EventLimits, SignedEvent, UnsignedEvent, xonly_public_key},
    gift_wrap::open_gift_wrap,
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
async fn signed_recipient_metadata_routes_away_from_the_bootstrap_relay() {
    let bootstrap_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let recipient_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let bootstrap_url = format!("ws://{}", bootstrap_listener.local_addr().unwrap());
    let recipient_url = format!("ws://{}", recipient_listener.local_addr().unwrap());
    let bootstrap = tokio::spawn(serve_bootstrap_inbox(bootstrap_listener));
    let recipient_relay = tokio::spawn(serve_recipient_relay(recipient_listener));
    let state = tempdir().unwrap();
    let core = DaemonCore::open(
        state.path(),
        DaemonConfig {
            storage_provider: StorageProviderConfig::File,
            dm_relays: vec![bootstrap_url],
            ..DaemonConfig::default()
        },
        EventHub::default(),
    )
    .await
    .unwrap();
    let now = unix_now();
    let recipient_secret = [61; 32];
    let recipient = xonly_public_key(&recipient_secret).unwrap();
    let relay_list = UnsignedEvent::new(
        hex::encode(recipient),
        now,
        NIP17_DM_RELAY_LIST_KIND,
        vec![vec!["relay".into(), recipient_url]],
        String::new(),
        &EventLimits::default(),
    )
    .unwrap()
    .sign_with_aux(&recipient_secret, &[62; 32], &EventLimits::default())
    .unwrap();
    assert_eq!(
        core.remember_dm_relay_list(&relay_list, &recipient, now)
            .unwrap(),
        CacheMutation::Stored
    );

    let (inbound, _inbound_receiver) = tokio::sync::mpsc::channel(8);
    let service = core
        .start_dm_inbox(inbound)
        .await
        .unwrap()
        .expect("bootstrap inbox starts");
    let sent = command(
        &core,
        Command::Send {
            conversation: hex::encode(recipient),
            text: "recipient route wins".into(),
        },
    )
    .await;
    assert_eq!(sent["delivery"], "stored");

    core.prepare_for_shutdown().await;
    service.shutdown().await.unwrap();
    timeout(Duration::from_secs(2), bootstrap)
        .await
        .expect("bootstrap closes")
        .expect("bootstrap task");
    let event = timeout(Duration::from_secs(2), recipient_relay)
        .await
        .expect("recipient relay closes")
        .expect("recipient relay task");
    assert_eq!(event.id, sent["id"]);
    let opened = open_gift_wrap(
        &event,
        &recipient_secret,
        unix_now() + 1,
        &EventLimits::default(),
    )
    .unwrap();
    assert_eq!(opened.rumor.content, "recipient route wins");
}

async fn command(core: &DaemonCore, command: Command) -> Value {
    match core
        .handle(Request {
            version: VERSION,
            id: "recipient-route-test".into(),
            command,
        })
        .await
    {
        ResponseOutcome::Ok { result } => result,
        ResponseOutcome::Error { error } => panic!("daemon error: {}", error.message),
    }
}

async fn serve_bootstrap_inbox(listener: TcpListener) {
    let (stream, _) = listener.accept().await.unwrap();
    let mut socket = accept_async(stream).await.unwrap();
    authenticate(&mut socket, "bootstrap-inbox").await;
    let request = next_json(&mut socket).await;
    assert_eq!(request[0], "REQ");
    while let Some(message) = socket.next().await {
        match message {
            Ok(Message::Text(text)) => {
                let frame: Value = serde_json::from_str(&text).unwrap();
                assert_ne!(frame[0], "EVENT", "bootstrap received recipient DM");
            }
            Ok(Message::Ping(payload)) => socket.send(Message::Pong(payload)).await.unwrap(),
            Ok(Message::Close(_)) | Err(_) => break,
            Ok(_) => {}
        }
    }
}

async fn serve_recipient_relay(listener: TcpListener) -> SignedEvent {
    let (stream, _) = listener.accept().await.unwrap();
    let mut socket = accept_async(stream).await.unwrap();
    authenticate(&mut socket, "recipient-delivery").await;
    let publish = next_json(&mut socket).await;
    assert_eq!(publish[0], "EVENT");
    let event: SignedEvent = serde_json::from_value(publish[1].clone()).unwrap();
    event
        .verify(unix_now() + 1, &EventLimits::default())
        .unwrap();
    socket
        .send(Message::Text(
            json!(["OK", event.id, true, "stored"]).to_string().into(),
        ))
        .await
        .unwrap();
    while let Some(message) = socket.next().await {
        match message {
            Ok(Message::Ping(payload)) => socket.send(Message::Pong(payload)).await.unwrap(),
            Ok(Message::Close(_)) | Err(_) => break,
            Ok(_) => {}
        }
    }
    event
}

async fn authenticate(socket: &mut WebSocketStream<TcpStream>, challenge: &str) {
    socket
        .send(Message::Text(json!(["AUTH", challenge]).to_string().into()))
        .await
        .unwrap();
    let frame = next_json(socket).await;
    assert_eq!(frame[0], "AUTH");
    let event: SignedEvent = serde_json::from_value(frame[1].clone()).unwrap();
    event
        .verify(unix_now() + 1, &EventLimits::default())
        .unwrap();
    socket
        .send(Message::Text(
            json!(["OK", event.id, true, "authenticated"])
                .to_string()
                .into(),
        ))
        .await
        .unwrap();
}

async fn next_json(socket: &mut WebSocketStream<TcpStream>) -> Value {
    loop {
        match socket.next().await {
            Some(Ok(Message::Text(text))) => return serde_json::from_str(&text).unwrap(),
            Some(Ok(Message::Ping(payload))) => socket.send(Message::Pong(payload)).await.unwrap(),
            Some(Ok(Message::Close(frame))) => panic!("relay closed early: {frame:?}"),
            Some(Ok(_)) => {}
            Some(Err(error)) => panic!("relay failed: {error}"),
            None => panic!("relay ended early"),
        }
    }
}

fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs()
}
