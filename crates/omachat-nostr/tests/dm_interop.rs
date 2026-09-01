use futures_util::{SinkExt, StreamExt};
use omachat_nostr::{
    auth::{NIP42_AUTH_KIND, RelayAuthSigner},
    discovery::NIP17_DM_RELAY_LIST_KIND,
    dm_delivery::AuthenticatedDmDelivery,
    dm_relay_routing::route_verified_dm_inbox,
    dm_routed_publish::plan_routed_dm_publish,
    event::{EventLimits, SignedEvent, UnsignedEvent, xonly_public_key},
    gift_wrap::{
        ChatRecipient, GiftWrapMaterial, GiftWrapPersistence, create_chat_rumor,
        create_gift_wrap_with_material, open_gift_wrap,
    },
    inbox::{DmInboxPolicy, verify_dm_inbox},
    relay::RelayRoute,
};
use serde_json::{Value, json};
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tokio::net::{TcpListener, TcpStream};
use tokio_tungstenite::{WebSocketStream, accept_async, tungstenite::Message};

fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

async fn next_json(socket: &mut WebSocketStream<TcpStream>) -> Value {
    loop {
        match socket.next().await.unwrap().unwrap() {
            Message::Text(text) => return serde_json::from_str(&text).unwrap(),
            Message::Ping(payload) => socket.send(Message::Pong(payload)).await.unwrap(),
            other => panic!("unexpected interoperability frame: {other:?}"),
        }
    }
}

async fn authenticated_inbox_relay(
    listener: TcpListener,
    relay_url: String,
    challenge: String,
    expected_sender: String,
) -> SignedEvent {
    let (stream, _) = listener.accept().await.unwrap();
    let mut socket = accept_async(stream).await.unwrap();
    socket
        .send(Message::Text(json!(["AUTH", challenge]).to_string().into()))
        .await
        .unwrap();

    let auth_frame = next_json(&mut socket).await;
    assert_eq!(auth_frame[0], "AUTH");
    let auth: SignedEvent = serde_json::from_value(auth_frame[1].clone()).unwrap();
    auth.verify(now(), &EventLimits::default()).unwrap();
    assert_eq!(auth.kind, NIP42_AUTH_KIND);
    assert_eq!(auth.pubkey, expected_sender);
    assert_eq!(
        auth.tags,
        vec![
            vec!["relay".to_owned(), relay_url],
            vec!["challenge".to_owned(), challenge],
        ]
    );
    socket
        .send(Message::Text(
            json!(["OK", auth.id, true, "authenticated"])
                .to_string()
                .into(),
        ))
        .await
        .unwrap();

    let publish_frame = next_json(&mut socket).await;
    assert_eq!(publish_frame[0], "EVENT");
    let gift_wrap: SignedEvent = serde_json::from_value(publish_frame[1].clone()).unwrap();
    gift_wrap.verify(now(), &EventLimits::default()).unwrap();
    socket
        .send(Message::Text(
            json!(["OK", gift_wrap.id, true, "stored"])
                .to_string()
                .into(),
        ))
        .await
        .unwrap();
    while let Some(Ok(message)) = socket.next().await {
        if matches!(message, Message::Close(_)) {
            break;
        }
    }
    gift_wrap
}

#[tokio::test]
async fn external_identity_crosses_two_authenticated_inbox_relays_unchanged() {
    // This key is supplied as an already-existing external Nostr identity. No
    // OmaChat account or replacement key is manufactured for it.
    let external_sender_secret = [0x41; 32];
    let recipient_secret = [0x42; 32];
    let external_sender = hex::encode(xonly_public_key(&external_sender_secret).unwrap());
    let recipient = xonly_public_key(&recipient_secret).unwrap();
    let timestamp = now();
    let limits = EventLimits::default();

    let first_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let second_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let first_url = format!("ws://{}/", first_listener.local_addr().unwrap());
    let second_url = format!("ws://{}/", second_listener.local_addr().unwrap());
    let first_server = tokio::spawn(authenticated_inbox_relay(
        first_listener,
        first_url.clone(),
        "first-inbox".to_owned(),
        external_sender.clone(),
    ));
    let second_server = tokio::spawn(authenticated_inbox_relay(
        second_listener,
        second_url.clone(),
        "second-inbox".to_owned(),
        external_sender.clone(),
    ));

    let inbox_event = UnsignedEvent::new(
        hex::encode(recipient),
        timestamp - 1,
        NIP17_DM_RELAY_LIST_KIND,
        vec![
            vec!["relay".to_owned(), first_url],
            vec!["relay".to_owned(), second_url],
        ],
        String::new(),
        &limits,
    )
    .unwrap()
    .sign_with_aux(&recipient_secret, &[0x43; 32], &limits)
    .unwrap();
    let inbox = verify_dm_inbox(
        &inbox_event,
        &recipient,
        timestamp,
        &limits,
        &DmInboxPolicy {
            require_tls: false,
            ..DmInboxPolicy::default()
        },
    )
    .unwrap();

    let rumor = create_chat_rumor(
        &external_sender_secret,
        timestamp,
        &[ChatRecipient {
            public_key: recipient,
            relay_hint: None,
        }],
        "hello from an external Nostr agent".to_owned(),
        None,
        None,
        &limits,
    )
    .unwrap();
    let gift_wrap = create_gift_wrap_with_material(
        &rumor,
        &external_sender_secret,
        &recipient,
        GiftWrapPersistence::Persistent,
        GiftWrapMaterial {
            seal_created_at: timestamp - 2,
            seal_nonce: [0x44; 32],
            seal_auxiliary_randomness: [0x45; 32],
            wrapper_secret_key: [0x46; 32],
            wrapper_created_at: timestamp - 3,
            wrapper_nonce: [0x47; 32],
            wrapper_auxiliary_randomness: [0x48; 32],
        },
        &limits,
    )
    .unwrap();
    let route = route_verified_dm_inbox(&inbox).unwrap();
    let plan = plan_routed_dm_publish(gift_wrap, route, timestamp, &limits).unwrap();
    assert_eq!(plan.required_acknowledgements(), 2);

    let auth = RelayAuthSigner::from_secret_key(external_sender_secret).unwrap();
    let mut delivery = AuthenticatedDmDelivery::spawn(plan, RelayRoute::Direct, auth).unwrap();
    delivery
        .wait_until_authenticated(Duration::from_secs(2))
        .await
        .unwrap();
    let result = delivery.publish().await.unwrap();
    assert_eq!(result.accepted, 2);
    assert_eq!(result.attempted, 2);
    for outcome in delivery.shutdown().await {
        outcome.unwrap();
    }

    let first_copy = first_server.await.unwrap();
    let second_copy = second_server.await.unwrap();
    assert_eq!(first_copy.id, second_copy.id);
    let opened = open_gift_wrap(&first_copy, &recipient_secret, now(), &limits).unwrap();
    assert_eq!(opened.rumor.id, rumor.id);
    assert_eq!(opened.rumor.pubkey, external_sender);
    assert_eq!(opened.seal.pubkey, external_sender);
    assert_eq!(opened.rumor.content, "hello from an external Nostr agent");
}
