use std::time::{Duration, SystemTime, UNIX_EPOCH};

use futures_util::{SinkExt, StreamExt};
use omachat_nostr::{
    auth::{NIP42_AUTH_KIND, RelayAuthSigner},
    discovery::NIP17_DM_RELAY_LIST_KIND,
    dm_relay_routing::route_verified_dm_inbox,
    dm_routed_publish::{RoutedDmPublishPlan, plan_routed_dm_publish},
    event::{EventLimits, SignedEvent, UnsignedEvent, xonly_public_key},
    gift_wrap::{ChatRecipient, GiftWrapPersistence, create_chat_rumor, create_gift_wrap},
    inbox::{DmInboxPolicy, verify_dm_inbox},
    relay::RelayRoute,
};
use omachatd::{DmDeliveryService, DmDeliveryServiceConfig, DmDeliveryServiceError};
use serde_json::{Value, json};
use tokio::{
    net::{TcpListener, TcpStream},
    sync::oneshot,
    time::timeout,
};
use tokio_tungstenite::{WebSocketStream, accept_async, tungstenite::Message};

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn publishes_the_exact_recipient_bound_event_and_joins_relays() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let relay_url = format!("ws://{}/", listener.local_addr().unwrap());
    let sender_secret = [51; 32];
    let recipient_secret = [52; 32];
    let now = unix_now();
    let plan = plan(&relay_url, sender_secret, recipient_secret, now);
    let expected = plan.event().clone();
    let relay = tokio::spawn(accept_publish(
        listener,
        hex::encode(xonly_public_key(&sender_secret).unwrap()),
    ));
    let service = DmDeliveryService::spawn(
        RelayAuthSigner::from_secret_key(sender_secret).unwrap(),
        DmDeliveryServiceConfig {
            authentication_timeout: Duration::from_secs(2),
            transport_route: RelayRoute::Direct,
        },
    )
    .unwrap();

    let result = service.handle().publish(plan).await.unwrap();
    assert_eq!(result.accepted, 1);
    assert_eq!(result.attempted, 1);
    service.shutdown().await.unwrap();
    assert_eq!(
        timeout(Duration::from_secs(2), relay)
            .await
            .unwrap()
            .unwrap(),
        expected
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn shutdown_cancels_authentication_and_joins_the_connection() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let relay_url = format!("ws://{}/", listener.local_addr().unwrap());
    let sender_secret = [53; 32];
    let plan = plan(&relay_url, sender_secret, [54; 32], unix_now());
    let (authenticated, authenticated_receiver) = oneshot::channel();
    let relay = tokio::spawn(hold_authentication(listener, authenticated));
    let service = DmDeliveryService::spawn(
        RelayAuthSigner::from_secret_key(sender_secret).unwrap(),
        DmDeliveryServiceConfig {
            authentication_timeout: Duration::from_secs(30),
            transport_route: RelayRoute::Direct,
        },
    )
    .unwrap();
    let publish = tokio::spawn({
        let handle = service.handle();
        async move { handle.publish(plan).await }
    });
    timeout(Duration::from_secs(2), authenticated_receiver)
        .await
        .expect("relay observed authentication")
        .expect("authentication signal");

    timeout(Duration::from_secs(2), service.shutdown())
        .await
        .expect("service joins active relay")
        .expect("service shutdown");
    assert!(matches!(
        publish.await.unwrap(),
        Err(DmDeliveryServiceError::Stopped)
    ));
    timeout(Duration::from_secs(2), relay)
        .await
        .expect("relay observes closure")
        .expect("relay task");
}

fn plan(
    relay_url: &str,
    sender_secret: [u8; 32],
    recipient_secret: [u8; 32],
    now: u64,
) -> RoutedDmPublishPlan {
    let limits = EventLimits::default();
    let recipient = xonly_public_key(&recipient_secret).unwrap();
    let relay_list = UnsignedEvent::new(
        hex::encode(recipient),
        now,
        NIP17_DM_RELAY_LIST_KIND,
        vec![vec!["relay".into(), relay_url.into()]],
        String::new(),
        &limits,
    )
    .unwrap()
    .sign_with_aux(&recipient_secret, &[55; 32], &limits)
    .unwrap();
    let inbox = verify_dm_inbox(
        &relay_list,
        &recipient,
        now,
        &limits,
        &DmInboxPolicy {
            require_tls: false,
            ..DmInboxPolicy::default()
        },
    )
    .unwrap();
    let rumor = create_chat_rumor(
        &sender_secret,
        now,
        &[ChatRecipient {
            public_key: recipient,
            relay_hint: None,
        }],
        "recipient-routed delivery".into(),
        None,
        None,
        &limits,
    )
    .unwrap();
    let gift_wrap = create_gift_wrap(
        &rumor,
        &sender_secret,
        &recipient,
        now,
        GiftWrapPersistence::Persistent,
        &limits,
    )
    .unwrap();
    plan_routed_dm_publish(
        gift_wrap,
        route_verified_dm_inbox(&inbox).unwrap(),
        now,
        &limits,
    )
    .unwrap()
}

async fn accept_publish(listener: TcpListener, expected_sender: String) -> SignedEvent {
    let (stream, _) = listener.accept().await.unwrap();
    let mut socket = accept_async(stream).await.unwrap();
    socket
        .send(Message::Text(json!(["AUTH", "publish"]).to_string().into()))
        .await
        .unwrap();
    let auth = next_json(&mut socket).await;
    let auth_event: SignedEvent = serde_json::from_value(auth[1].clone()).unwrap();
    assert_eq!(auth_event.kind, NIP42_AUTH_KIND);
    assert_eq!(auth_event.pubkey, expected_sender);
    socket
        .send(Message::Text(
            json!(["OK", auth_event.id, true, "authenticated"])
                .to_string()
                .into(),
        ))
        .await
        .unwrap();
    let publish = next_json(&mut socket).await;
    assert_eq!(publish[0], "EVENT");
    let event: SignedEvent = serde_json::from_value(publish[1].clone()).unwrap();
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

async fn hold_authentication(listener: TcpListener, authenticated: oneshot::Sender<()>) {
    let (stream, _) = listener.accept().await.unwrap();
    let mut socket = accept_async(stream).await.unwrap();
    socket
        .send(Message::Text(json!(["AUTH", "hold"]).to_string().into()))
        .await
        .unwrap();
    let auth = next_json(&mut socket).await;
    assert_eq!(auth[0], "AUTH");
    let _ = authenticated.send(());
    while let Some(message) = socket.next().await {
        match message {
            Ok(Message::Ping(payload)) => socket.send(Message::Pong(payload)).await.unwrap(),
            Ok(Message::Close(_)) | Err(_) => break,
            Ok(_) => {}
        }
    }
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
