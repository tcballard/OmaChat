use std::time::{Duration, SystemTime, UNIX_EPOCH};

use futures_util::{SinkExt, StreamExt};
use omachat_nostr::{
    auth::RelayAuthSigner,
    event::{EventLimits, SignedEvent, UnsignedEvent, xonly_public_key},
    profile_discovery::{ProfileDiscoveryConfig, discover_profile_metadata},
    profile_metadata::PROFILE_METADATA_KIND,
    profile_verification::ProfileNameClassification,
    relay::{RelayAuthenticationPolicy, RelayConfig, RelayRoute},
};
use serde_json::{Value, json};
use tokio::net::{TcpListener, TcpStream};
use tokio_tungstenite::{WebSocketStream, accept_async, tungstenite::Message};

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn chooses_the_newest_valid_external_profile_after_every_eose() {
    let participant_secret = [101; 32];
    let participant = xonly_public_key(&participant_secret).unwrap();
    let now = unix_now();
    let older = profile(participant_secret, now - 2, "old-agent", "Old Agent", 102);
    let newer = profile(
        participant_secret,
        now - 1,
        "shared-agent",
        "Shared Agent",
        103,
    );
    let forged = profile([104; 32], now, "impostor", "Impostor", 105);
    let first_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let second_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let first_url = format!("ws://{}", first_listener.local_addr().unwrap());
    let second_url = format!("ws://{}", second_listener.local_addr().unwrap());
    let first = tokio::spawn(serve_query(first_listener, vec![forged, older]));
    let second = tokio::spawn(serve_query(second_listener, vec![newer.clone()]));
    let result = discover_profile_metadata(
        vec![relay(&first_url), relay(&second_url)],
        RelayAuthSigner::from_secret_key([106; 32]).unwrap(),
        &participant,
        now,
        &EventLimits::default(),
        &ProfileDiscoveryConfig {
            authentication_timeout: Duration::from_secs(2),
            authentication_policy: RelayAuthenticationPolicy::AuthenticateWhenChallenged,
            challenge_settle_timeout: Duration::from_millis(25),
            query_timeout: Duration::from_secs(2),
            minimum_ready_relays: 2,
            subscription_id: "external-profile-query".into(),
        },
    )
    .await
    .unwrap();
    assert_eq!(result.event, newer);
    assert_eq!(result.profile.public_key(), &participant);
    assert_eq!(result.profile.nostr_name(), Some("shared-agent"));
    assert_eq!(result.profile.display_name(), Some("Shared Agent"));
    assert_eq!(
        result.profile.name_classification(),
        Some(ProfileNameClassification::HandleSyntaxCandidate)
    );
    assert_eq!(result.queried_relays, 2);
    assert_eq!(result.completed_relays, 2);
    first.await.unwrap();
    second.await.unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn public_relay_without_an_auth_challenge_remains_discoverable() {
    let participant_secret = [107; 32];
    let participant = xonly_public_key(&participant_secret).unwrap();
    let now = unix_now();
    let expected = profile(
        participant_secret,
        now - 1,
        "public-agent",
        "Public Agent",
        108,
    );
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!("ws://{}", listener.local_addr().unwrap());
    let server = tokio::spawn(serve_public_query(listener, expected.clone()));

    let result = discover_profile_metadata(
        vec![relay(&url)],
        RelayAuthSigner::from_secret_key([109; 32]).unwrap(),
        &participant,
        now,
        &EventLimits::default(),
        &ProfileDiscoveryConfig {
            authentication_timeout: Duration::from_secs(2),
            authentication_policy: RelayAuthenticationPolicy::AuthenticateWhenChallenged,
            challenge_settle_timeout: Duration::from_millis(25),
            query_timeout: Duration::from_secs(2),
            minimum_ready_relays: 1,
            subscription_id: "public-profile-query".into(),
        },
    )
    .await
    .unwrap();

    assert_eq!(result.event, expected);
    assert_eq!(result.queried_relays, 1);
    assert_eq!(result.completed_relays, 1);
    server.await.unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn one_completed_relay_is_not_blocked_by_a_stalled_optional_relay() {
    let participant_secret = [110; 32];
    let participant = xonly_public_key(&participant_secret).unwrap();
    let now = unix_now();
    let expected = profile(
        participant_secret,
        now - 1,
        "resilient-agent",
        "Resilient Agent",
        111,
    );
    let completed_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let stalled_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let completed_url = format!("ws://{}", completed_listener.local_addr().unwrap());
    let stalled_url = format!("ws://{}", stalled_listener.local_addr().unwrap());
    let completed = tokio::spawn(serve_public_query(completed_listener, expected.clone()));
    let stalled = tokio::spawn(serve_public_query_without_eose(stalled_listener));

    let result = discover_profile_metadata(
        vec![relay(&completed_url), relay(&stalled_url)],
        RelayAuthSigner::from_secret_key([112; 32]).unwrap(),
        &participant,
        now,
        &EventLimits::default(),
        &ProfileDiscoveryConfig {
            authentication_timeout: Duration::from_secs(2),
            authentication_policy: RelayAuthenticationPolicy::AuthenticateWhenChallenged,
            challenge_settle_timeout: Duration::from_millis(25),
            query_timeout: Duration::from_secs(2),
            minimum_ready_relays: 1,
            subscription_id: "resilient-profile-query".into(),
        },
    )
    .await
    .unwrap();

    assert_eq!(result.event, expected);
    assert_eq!(result.queried_relays, 2);
    assert_eq!(result.completed_relays, 1);
    completed.await.unwrap();
    stalled.abort();
}

fn relay(url: &str) -> RelayConfig {
    let mut config = RelayConfig::new(url.into(), RelayRoute::Direct);
    config.connect_timeout = Duration::from_secs(1);
    config.response_timeout = Duration::from_secs(1);
    config.shutdown_timeout = Duration::from_secs(1);
    config
}

fn profile(
    secret: [u8; 32],
    created_at: u64,
    name: &str,
    display_name: &str,
    auxiliary: u8,
) -> SignedEvent {
    UnsignedEvent::new(
        hex::encode(xonly_public_key(&secret).unwrap()),
        created_at,
        PROFILE_METADATA_KIND,
        Vec::new(),
        json!({"name": name, "display_name": display_name}).to_string(),
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
            json!(["AUTH", "discover-profile"]).to_string().into(),
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
    assert_eq!(request[2]["kinds"], json!([PROFILE_METADATA_KIND]));
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

async fn serve_public_query(listener: TcpListener, event: SignedEvent) {
    let (stream, _) = listener.accept().await.unwrap();
    let mut socket = accept_async(stream).await.unwrap();
    let request = next_json(&mut socket).await;
    assert_eq!(request[0], "REQ");
    assert_eq!(request[2]["kinds"], json!([PROFILE_METADATA_KIND]));
    let subscription_id = request[1].as_str().unwrap();
    socket
        .send(Message::Text(
            json!(["EVENT", subscription_id, event]).to_string().into(),
        ))
        .await
        .unwrap();
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

async fn serve_public_query_without_eose(listener: TcpListener) {
    let (stream, _) = listener.accept().await.unwrap();
    let mut socket = accept_async(stream).await.unwrap();
    let request = next_json(&mut socket).await;
    assert_eq!(request[0], "REQ");
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
