use std::time::{Duration, SystemTime, UNIX_EPOCH};

use futures_util::{SinkExt, StreamExt};
use omachat_nostr::{
    auth::RelayAuthSigner,
    dm_inbox::DmInboxReceive,
    dm_inbox_runtime::{AuthenticatedDmInboxRuntime, DmInboxRuntimeConfig, DmInboxRuntimeError},
    event::{EventLimits, SignedEvent},
    gift_wrap::{ChatRecipient, GiftWrapPersistence, create_chat_rumor, create_gift_wrap},
    relay::{RelayConfig, RelayRoute},
};
use serde_json::{Value, json};
use tokio::{
    net::{TcpListener, TcpStream},
    task::JoinHandle,
    time::timeout,
};
use tokio_tungstenite::{WebSocketStream, accept_async, tungstenite::Message};

#[derive(Debug)]
struct RelayObservation {
    auth_public_key: String,
    request: Option<Value>,
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn authenticates_all_relays_before_subscribing_and_deduplicates() {
    let now = unix_now();
    let limits = EventLimits::default();
    let recipient_secret_key = [7_u8; 32];
    let sender_secret_key = [9_u8; 32];
    let recipient_signer = RelayAuthSigner::from_secret_key(recipient_secret_key).unwrap();
    let recipient_public_key = *recipient_signer.public_key();
    let recipient_public_key_hex = hex::encode(recipient_public_key);
    let sender_public_key_hex = hex::encode(
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
        "one event over two relay paths".to_owned(),
        None,
        None,
        &limits,
    )
    .unwrap();
    let gift_wrap = create_gift_wrap(
        &rumor,
        &sender_secret_key,
        &recipient_public_key,
        now,
        GiftWrapPersistence::Persistent,
        &limits,
    )
    .unwrap();

    let (relay_one, relay_one_task) = spawn_relay(Some(gift_wrap.clone()), false).await;
    let (relay_two, relay_two_task) = spawn_relay(Some(gift_wrap), false).await;
    let mut runtime = AuthenticatedDmInboxRuntime::connect(
        vec![relay_one, relay_two],
        recipient_signer,
        recipient_secret_key,
        fast_runtime_config(),
        now,
    )
    .await
    .unwrap();

    assert_eq!(runtime.recipient_public_key(), recipient_public_key_hex);
    assert_eq!(runtime.relay_count(), 2);

    let delivered = timeout(Duration::from_secs(2), runtime.next(now + 1))
        .await
        .unwrap()
        .unwrap();
    let DmInboxReceive::Message(message) = delivered.receive else {
        panic!("expected an authenticated message");
    };
    assert_eq!(message.content, "one event over two relay paths");
    assert_eq!(message.metadata.author_pubkey, sender_public_key_hex);
    assert!(delivered.relay_index < 2);

    assert!(
        timeout(Duration::from_millis(150), runtime.next(now + 1))
            .await
            .is_err()
    );

    let shutdown = runtime.shutdown().await;
    assert_eq!(shutdown.len(), 2);
    assert!(shutdown.into_iter().all(|result| result.is_ok()));

    let observation_one = timeout(Duration::from_secs(2), relay_one_task)
        .await
        .unwrap()
        .unwrap();
    let observation_two = timeout(Duration::from_secs(2), relay_two_task)
        .await
        .unwrap()
        .unwrap();
    for observation in [observation_one, observation_two] {
        assert_eq!(observation.auth_public_key, recipient_public_key_hex);
        let request = observation
            .request
            .expect("subscription after authentication");
        assert_eq!(request[0], "REQ");
        assert_eq!(request[1], "omachat-nip17-inbox");
        assert_eq!(request[2]["kinds"], json!([1059]));
        assert_eq!(request[2]["#p"], json!([recipient_public_key_hex]));
        assert_eq!(request[2]["limit"], json!(500));
        assert!(request[2]["since"].as_u64().is_some());
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn authentication_rejection_fails_closed() {
    let now = unix_now();
    let recipient_secret_key = [11_u8; 32];
    let recipient_signer = RelayAuthSigner::from_secret_key(recipient_secret_key).unwrap();
    let recipient_public_key_hex = hex::encode(recipient_signer.public_key());
    let (relay, relay_task) = spawn_relay(None, true).await;

    let error = match AuthenticatedDmInboxRuntime::connect(
        vec![relay],
        recipient_signer,
        recipient_secret_key,
        fast_runtime_config(),
        now,
    )
    .await
    {
        Ok(runtime) => {
            let _ = runtime.shutdown().await;
            panic!("authentication rejection unexpectedly connected");
        }
        Err(error) => error,
    };
    assert!(matches!(
        error,
        DmInboxRuntimeError::AuthenticationRejected { relay_index: 0, .. }
    ));

    let observation = timeout(Duration::from_secs(2), relay_task)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(observation.auth_public_key, recipient_public_key_hex);
    assert!(observation.request.is_none());
}

#[tokio::test]
async fn mismatched_authentication_and_recipient_keys_are_rejected_before_connect() {
    let relay = RelayConfig::new("ws://127.0.0.1:9".to_owned(), RelayRoute::Direct);
    let error = match AuthenticatedDmInboxRuntime::connect(
        vec![relay],
        RelayAuthSigner::from_secret_key([13_u8; 32]).unwrap(),
        [17_u8; 32],
        fast_runtime_config(),
        unix_now(),
    )
    .await
    {
        Ok(runtime) => {
            let _ = runtime.shutdown().await;
            panic!("mismatched identities unexpectedly connected");
        }
        Err(error) => error,
    };
    assert!(matches!(error, DmInboxRuntimeError::IdentityMismatch));
}

fn fast_runtime_config() -> DmInboxRuntimeConfig {
    DmInboxRuntimeConfig {
        authentication_timeout: Duration::from_secs(2),
        ..DmInboxRuntimeConfig::default()
    }
}

async fn spawn_relay(
    gift_wrap: Option<SignedEvent>,
    reject_authentication: bool,
) -> (RelayConfig, JoinHandle<RelayObservation>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let url = format!("ws://{address}");
    let server_url = url.clone();
    let task = tokio::spawn(async move {
        serve_relay(listener, server_url, gift_wrap, reject_authentication).await
    });

    let mut relay = RelayConfig::new(url, RelayRoute::Direct);
    relay.connect_timeout = Duration::from_secs(1);
    relay.response_timeout = Duration::from_secs(1);
    relay.shutdown_timeout = Duration::from_secs(1);
    relay.reconnect_initial_delay = Duration::from_millis(25);
    relay.reconnect_max_delay = Duration::from_millis(100);
    (relay, task)
}

async fn serve_relay(
    listener: TcpListener,
    relay_url: String,
    gift_wrap: Option<SignedEvent>,
    reject_authentication: bool,
) -> RelayObservation {
    let (stream, _) = listener.accept().await.unwrap();
    let mut websocket = accept_async(stream).await.unwrap();
    websocket
        .send(Message::Text(
            json!(["AUTH", "omachat-runtime-test-challenge"])
                .to_string()
                .into(),
        ))
        .await
        .unwrap();

    let auth_frame = next_json(&mut websocket).await;
    assert_eq!(auth_frame[0], "AUTH", "subscription arrived before AUTH");
    let auth_event: SignedEvent = serde_json::from_value(auth_frame[1].clone()).unwrap();
    assert_eq!(auth_event.kind, 22242);
    auth_event
        .verify(unix_now() + 1, &EventLimits::default())
        .unwrap();

    websocket
        .send(Message::Text(
            json!([
                "OK",
                auth_event.id,
                !reject_authentication,
                if reject_authentication {
                    "auth rejected by test relay"
                } else {
                    ""
                }
            ])
            .to_string()
            .into(),
        ))
        .await
        .unwrap();

    if reject_authentication {
        return RelayObservation {
            auth_public_key: auth_event.pubkey,
            request: None,
        };
    }

    let request = next_json(&mut websocket).await;
    assert_eq!(request[0], "REQ");
    if let Some(gift_wrap) = gift_wrap {
        websocket
            .send(Message::Text(
                json!(["EVENT", request[1], gift_wrap]).to_string().into(),
            ))
            .await
            .unwrap();
    }

    while let Some(message) = websocket.next().await {
        match message {
            Ok(Message::Ping(payload)) => {
                websocket.send(Message::Pong(payload)).await.unwrap();
            }
            Ok(Message::Close(_)) | Err(_) => break,
            Ok(_) => {}
        }
    }

    assert!(relay_url.starts_with("ws://"));
    RelayObservation {
        auth_public_key: auth_event.pubkey,
        request: Some(request),
    }
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
                panic!("relay connection closed before expected frame: {frame:?}");
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
