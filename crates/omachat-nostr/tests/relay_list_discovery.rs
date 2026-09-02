use std::time::{Duration, SystemTime, UNIX_EPOCH};

use futures_util::{SinkExt, StreamExt};
use omachat_nostr::{
    auth::RelayAuthSigner,
    discovery::{NIP65_RELAY_LIST_KIND, RelayDiscoveryLimits, RelayPreference},
    event::{EventLimits, SignedEvent, xonly_public_key},
    relay::{RelayAuthenticationPolicy, RelayConfig, RelayRoute},
    relay_list::create_nip65_relay_list_with_aux,
    relay_list_discovery::{RelayListDiscoveryConfig, discover_nip65_relay_list},
};
use serde_json::{Value, json};
use tokio::net::{TcpListener, TcpStream};
use tokio_tungstenite::{WebSocketStream, accept_async, tungstenite::Message};

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn chooses_the_newest_valid_external_list_after_every_relay_completes() {
    let participant_secret = [81; 32];
    let participant = xonly_public_key(&participant_secret).unwrap();
    let participant_hex = hex::encode(participant);
    let now = unix_now();
    let older = relay_list(
        participant_secret,
        now - 2,
        "wss://older.example",
        true,
        false,
        82,
    );
    let newer = relay_list(
        participant_secret,
        now - 1,
        "wss://current.example",
        true,
        true,
        83,
    );
    let forged = relay_list([84; 32], now, "wss://attacker.example", true, true, 85);
    let first_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let second_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let first_url = format!("ws://{}", first_listener.local_addr().unwrap());
    let second_url = format!("ws://{}", second_listener.local_addr().unwrap());
    let first = tokio::spawn(serve_query(
        first_listener,
        participant_hex.clone(),
        vec![forged, older],
    ));
    let second = tokio::spawn(serve_query(
        second_listener,
        participant_hex.clone(),
        vec![newer.clone()],
    ));

    let result = discover_nip65_relay_list(
        vec![relay_config(&first_url), relay_config(&second_url)],
        RelayAuthSigner::from_secret_key([86; 32]).unwrap(),
        &participant,
        now,
        &EventLimits::default(),
        &RelayDiscoveryLimits::default(),
        &RelayListDiscoveryConfig {
            authentication_timeout: Duration::from_secs(2),
            authentication_policy: RelayAuthenticationPolicy::RequireWhenConfigured,
            challenge_settle_timeout: Duration::from_millis(25),
            query_timeout: Duration::from_secs(2),
            minimum_ready_relays: 2,
            subscription_id: "external-nip65-query".into(),
        },
    )
    .await
    .unwrap();

    assert_eq!(result.event, newer);
    assert_eq!(result.relay_list.public_key, participant_hex);
    assert_eq!(
        result.relay_list.relays,
        vec![RelayPreference {
            url: "wss://current.example/".into(),
            read: true,
            write: true,
        }]
    );
    assert_eq!(result.queried_relays, 2);
    assert_eq!(result.completed_relays, 2);
    first.await.unwrap();
    second.await.unwrap();
}

fn relay_config(url: &str) -> RelayConfig {
    let mut config = RelayConfig::new(url.into(), RelayRoute::Direct);
    config.connect_timeout = Duration::from_secs(1);
    config.response_timeout = Duration::from_secs(1);
    config.shutdown_timeout = Duration::from_secs(1);
    config
}

fn relay_list(
    secret: [u8; 32],
    created_at: u64,
    url: &str,
    read: bool,
    write: bool,
    auxiliary: u8,
) -> SignedEvent {
    create_nip65_relay_list_with_aux(
        &secret,
        created_at,
        &[RelayPreference {
            url: url.into(),
            read,
            write,
        }],
        &[auxiliary; 32],
        &EventLimits::default(),
        &RelayDiscoveryLimits::default(),
    )
    .unwrap()
}

async fn serve_query(listener: TcpListener, expected_author: String, events: Vec<SignedEvent>) {
    let (stream, _) = listener.accept().await.unwrap();
    let mut socket = accept_async(stream).await.unwrap();
    socket
        .send(Message::Text(
            json!(["AUTH", "discover-nip65"]).to_string().into(),
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
    assert_eq!(request[2]["kinds"], json!([NIP65_RELAY_LIST_KIND]));
    assert_eq!(request[2]["authors"], json!([expected_author]));
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
