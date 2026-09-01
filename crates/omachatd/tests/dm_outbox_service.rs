use std::time::{Duration, SystemTime, UNIX_EPOCH};

use futures_util::{SinkExt, StreamExt};
use omachat_nostr::{
    auth::RelayAuthSigner,
    discovery::NIP17_DM_RELAY_LIST_KIND,
    dm_inbox_runtime::DmInboxRuntimeConfig,
    dm_relay_routing::route_verified_dm_inbox,
    dm_routed_publish::plan_routed_dm_publish,
    event::{EventLimits, SignedEvent, UnsignedEvent},
    gift_wrap::{ChatRecipient, GiftWrapPersistence, create_chat_rumor, create_gift_wrap},
    inbox::{DmInboxPolicy, verify_dm_inbox},
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
async fn authenticated_service_publishes_only_the_bound_standard_recipient() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let relay_url = format!("ws://{}", listener.local_addr().unwrap());
    let relay_task = tokio::spawn(serve_relay(listener));
    let sender_secret_key = [31_u8; 32];
    let sender_signer = RelayAuthSigner::from_secret_key(sender_secret_key).unwrap();
    let recipient_secret_key = [37_u8; 32];
    let recipient_public_key = *RelayAuthSigner::from_secret_key(recipient_secret_key)
        .unwrap()
        .public_key();
    let recipient_public_key_hex = hex::encode(recipient_public_key);
    let now = unix_now();
    let rumor = create_chat_rumor(
        &sender_secret_key,
        now,
        &[ChatRecipient {
            public_key: recipient_public_key,
            relay_hint: Some(relay_url.clone()),
        }],
        "authenticated standard outbox".to_owned(),
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
    let relay_list = UnsignedEvent::new(
        recipient_public_key_hex.clone(),
        now,
        NIP17_DM_RELAY_LIST_KIND,
        vec![vec!["relay".into(), relay_url.clone()]],
        String::new(),
        &EventLimits::default(),
    )
    .unwrap()
    .sign_with_aux(&recipient_secret_key, &[43; 32], &EventLimits::default())
    .unwrap();
    let inbox = verify_dm_inbox(
        &relay_list,
        &recipient_public_key,
        now,
        &EventLimits::default(),
        &DmInboxPolicy {
            require_tls: false,
            ..DmInboxPolicy::default()
        },
    )
    .unwrap();
    let plan = plan_routed_dm_publish(
        gift_wrap.clone(),
        route_verified_dm_inbox(&inbox).unwrap(),
        now,
        &EventLimits::default(),
    )
    .unwrap();

    let mut relay = RelayConfig::new(relay_url, RelayRoute::Direct);
    relay.connect_timeout = Duration::from_secs(1);
    relay.response_timeout = Duration::from_secs(1);
    relay.shutdown_timeout = Duration::from_secs(1);
    let (inbound, _inbound_receiver) = tokio::sync::mpsc::channel(1);
    let service = DmInboxService::spawn_with_config(
        vec![relay],
        sender_signer,
        sender_secret_key,
        &[],
        DmInboxRuntimeConfig {
            authentication_timeout: Duration::from_secs(2),
            ..DmInboxRuntimeConfig::default()
        },
        inbound,
    )
    .await
    .unwrap();
    let handle = service.handle();

    handle.publish(plan).await.unwrap();
    service.shutdown().await.unwrap();
    let published = timeout(Duration::from_secs(2), relay_task)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(published, gift_wrap);
}

async fn serve_relay(listener: TcpListener) -> SignedEvent {
    let (inbound_stream, _) = listener.accept().await.unwrap();
    let inbound = tokio::spawn(async move {
        let mut websocket = accept_async(inbound_stream).await.unwrap();
        authenticate(&mut websocket, "daemon-inbox-test").await;
        let request = next_json(&mut websocket).await;
        assert_eq!(request[0], "REQ");
        assert_eq!(request[2]["kinds"], json!([1059]));
        wait_for_close(&mut websocket).await;
    });

    let (outbound_stream, _) = listener.accept().await.unwrap();
    let mut websocket = accept_async(outbound_stream).await.unwrap();
    authenticate(&mut websocket, "daemon-outbox-test").await;
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
