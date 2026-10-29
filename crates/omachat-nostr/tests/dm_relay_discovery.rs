use std::time::{Duration, SystemTime, UNIX_EPOCH};

use futures_util::{SinkExt, StreamExt};
use omachat_nostr::{
    auth::RelayAuthSigner,
    discovery::NIP17_DM_RELAY_LIST_KIND,
    dm_relay_discovery::{DmRelayDiscoveryConfig, discover_dm_relay_list},
    event::{EventLimits, SignedEvent, UnsignedEvent, xonly_public_key},
    inbox::DmInboxPolicy,
    relay::{RelayConfig, RelayRoute},
};
use serde_json::{Value, json};
use tokio::net::{TcpListener, TcpStream};
use tokio_tungstenite::{WebSocketStream, accept_async, tungstenite::Message};

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn chooses_the_newest_valid_recipient_event_after_every_eose() {
    let recipient_secret = [71; 32];
    let recipient = xonly_public_key(&recipient_secret).unwrap();
    let older = relay_list(recipient_secret, unix_now() - 2, "wss://older.example", 72);
    let newer = relay_list(recipient_secret, unix_now() - 1, "wss://newer.example", 73);
    let forged = relay_list([74; 32], unix_now(), "wss://attacker.example", 75);
    let first_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let second_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let first_url = format!("ws://{}", first_listener.local_addr().unwrap());
    let second_url = format!("ws://{}", second_listener.local_addr().unwrap());
    let first = tokio::spawn(serve_query(first_listener, vec![forged, older]));
    let second = tokio::spawn(serve_query(second_listener, vec![newer.clone()]));
    let auth = RelayAuthSigner::from_secret_key([76; 32]).unwrap();
    let result = discover_dm_relay_list(
        vec![relay(&first_url), relay(&second_url)],
        auth,
        &recipient,
        unix_now(),
        &EventLimits::default(),
        &DmInboxPolicy::default(),
        &DmRelayDiscoveryConfig {
            authentication_timeout: Duration::from_secs(2),
            query_timeout: Duration::from_secs(2),
            minimum_authenticated_relays: 2,
            subscription_id: "recipient-route-query".into(),
        },
    )
    .await
    .unwrap();
    assert_eq!(result.event, newer);
    assert_eq!(result.queried_relays, 2);
    assert_eq!(result.completed_relays, 2);
    first.await.unwrap();
    second.await.unwrap();
}

fn relay(url: &str) -> RelayConfig {
    let mut config = RelayConfig::new(url.into(), RelayRoute::Direct);
    config.connect_timeout = Duration::from_secs(1);
    config.response_timeout = Duration::from_secs(1);
    config.shutdown_timeout = Duration::from_secs(1);
    config
}

fn relay_list(secret: [u8; 32], created_at: u64, url: &str, auxiliary: u8) -> SignedEvent {
    UnsignedEvent::new(
        hex::encode(xonly_public_key(&secret).unwrap()),
        created_at,
        NIP17_DM_RELAY_LIST_KIND,
        vec![vec!["relay".into(), url.into()]],
        String::new(),
        &EventLimits::default(),
    )
    .unwrap()
    .sign_with_aux(&secret, &[auxiliary; 32], &EventLimits::default())
    .unwrap()
}

async fn serve_query(listener: TcpListener, events: Vec<SignedEvent>) {
    let (stream, _) = listener.accept().await.unwrap();
    let mut socket = accept_async(stream).await.unwrap();
    socket
        .send(Message::Text(
            json!(["AUTH", "discover-routes"]).to_string().into(),
        ))
        .await
        .unwrap();
    let authentication = next_json(&mut socket).await;
    assert_eq!(authentication[0], "AUTH");
    let auth_event: SignedEvent = serde_json::from_value(authentication[1].clone()).unwrap();
    auth_event
        .verify(unix_now() + 1, &EventLimits::default())
        .unwrap();
    socket
        .send(Message::Text(
            json!(["OK", auth_event.id, true, "authenticated"])
                .to_string()
                .into(),
        ))
        .await
        .unwrap();
    let request = next_json(&mut socket).await;
    assert_eq!(request[0], "REQ");
    assert_eq!(request[2]["kinds"], json!([NIP17_DM_RELAY_LIST_KIND]));
    assert_eq!(request[2]["limit"], 1);
    let subscription_id = request[1].as_str().unwrap();
    for event in events {
        socket
            .send(Message::Text(
                json!(["EVENT", subscription_id, event]).to_string().into(),
            ))
            .await
            .unwrap();
    }
    socket
        .send(Message::Text(
            json!(["EOSE", subscription_id]).to_string().into(),
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
