use std::time::{Duration, SystemTime, UNIX_EPOCH};

use futures_util::{SinkExt, StreamExt};
use omachat_nostr::{
    auth::RelayAuthSigner,
    dm_inbox::DmInboxReceive,
    dm_inbox_runtime::DmInboxRuntimeConfig,
    event::{EventLimits, SignedEvent},
    gift_wrap::{ChatRecipient, GiftWrapPersistence, create_chat_rumor, create_gift_wrap},
    relay::{RelayConfig, RelayRoute},
};
use omachatd::DmInboxService;
use serde_json::{Value, json};
use tokio::{
    net::{TcpListener, TcpStream},
    time::timeout,
};
use tokio_tungstenite::{WebSocketStream, accept_async, tungstenite::Message};

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn quiesce_waits_for_relay_shutdown_and_stops_plaintext_delivery() {
    let now = unix_now();
    let recipient_secret_key = [19_u8; 32];
    let sender_secret_key = [23_u8; 32];
    let recipient_signer = RelayAuthSigner::from_secret_key(recipient_secret_key).unwrap();
    let recipient_public_key = *recipient_signer.public_key();
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
        "daemon-owned private message".to_owned(),
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
    let (relay, relay_task) = spawn_relay(gift_wrap).await;
    let (inbound_sender, mut inbound_receiver) = tokio::sync::mpsc::channel(1);
    let service = DmInboxService::spawn_with_config(
        vec![relay],
        recipient_signer,
        recipient_secret_key,
        &[],
        DmInboxRuntimeConfig {
            authentication_timeout: Duration::from_secs(2),
            ..DmInboxRuntimeConfig::default()
        },
        inbound_sender,
    )
    .await
    .unwrap();

    let delivered = timeout(Duration::from_secs(2), inbound_receiver.recv())
        .await
        .unwrap()
        .expect("service forwards authenticated event");
    let DmInboxReceive::Message(message) = delivered.receive else {
        panic!("expected authenticated message");
    };
    assert_eq!(message.content, "daemon-owned private message");
    assert_eq!(message.metadata.author_pubkey, sender_public_key);

    let handle = service.handle();
    timeout(Duration::from_secs(2), handle.quiesce())
        .await
        .expect("quiesce waits for joined relay shutdown");
    timeout(Duration::from_secs(2), relay_task)
        .await
        .expect("test relay observes connection shutdown")
        .expect("test relay task");
    assert!(inbound_receiver.recv().await.is_none());
    service.shutdown().await.unwrap();
}

async fn spawn_relay(gift_wrap: SignedEvent) -> (RelayConfig, tokio::task::JoinHandle<()>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!("ws://{}", listener.local_addr().unwrap());
    let task = tokio::spawn(async move {
        let (stream, _) = listener.accept().await.unwrap();
        let mut websocket = accept_async(stream).await.unwrap();
        websocket
            .send(Message::Text(
                json!(["AUTH", "daemon-inbox-service-test"])
                    .to_string()
                    .into(),
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
    });

    let mut relay = RelayConfig::new(url, RelayRoute::Direct);
    relay.connect_timeout = Duration::from_secs(1);
    relay.response_timeout = Duration::from_secs(1);
    relay.shutdown_timeout = Duration::from_secs(1);
    (relay, task)
}

async fn next_json(websocket: &mut WebSocketStream<TcpStream>) -> Value {
    loop {
        match websocket.next().await {
            Some(Ok(Message::Text(text))) => {
                return serde_json::from_str(text.as_str()).unwrap();
            }
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
