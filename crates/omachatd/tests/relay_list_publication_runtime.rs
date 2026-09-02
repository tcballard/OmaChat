use std::{sync::Arc, time::Duration};

use futures_util::{SinkExt, StreamExt};
use omachat_nostr::{
    auth::RelayAuthSigner,
    discovery::NIP65_RELAY_LIST_KIND,
    event::{EventLimits, SignedEvent, UnsignedEvent, xonly_public_key},
};
use omachat_store::{RequestedProvider, SealedStore};
use omachatd::{
    NostrRelayListPublisherConfig, RelayListPublicationConfig, RelayListPublicationOutcomeStatus,
    RelayListPublicationRelayConfig, RelayListPublicationRuntime, RelayListPublicationRuntimeError,
};
use serde_json::{Value, json};
use tempfile::tempdir;
use tokio::net::{TcpListener, TcpStream};
use tokio_tungstenite::{WebSocketStream, accept_async, tungstenite::Message};

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn partial_publication_restarts_with_the_exact_event_and_remaining_relay() {
    let first_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let second_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let first_url = format!("ws://{}", first_listener.local_addr().unwrap());
    let second_url = format!("ws://{}", second_listener.local_addr().unwrap());
    let seen_events = Arc::new(std::sync::Mutex::new(Vec::new()));
    let first = tokio::spawn(serve_once(first_listener, true, Arc::clone(&seen_events)));
    let second = tokio::spawn(serve_twice(second_listener, Arc::clone(&seen_events)));
    let policy = policy(&first_url, &second_url);
    let secret = [171; 32];
    let state = tempdir().unwrap();
    let store = SealedStore::open(state.path(), RequestedProvider::File)
        .await
        .unwrap();
    let runtime = new_runtime(&secret, &policy);
    let now = unix_now();
    let event = runtime.create_event(&secret, now).unwrap();
    let first_outcome = runtime.publish(&store, &event, now).await.unwrap();
    assert_eq!(
        first_outcome.status,
        RelayListPublicationOutcomeStatus::Pending
    );
    assert_eq!(first_outcome.acknowledged_relays.len(), 1);
    assert_eq!(first_outcome.rejected_relays.len(), 1);
    runtime.shutdown().await.unwrap();
    drop(store);
    first.await.unwrap();

    let reopened = SealedStore::open(state.path(), RequestedProvider::File)
        .await
        .unwrap();
    let runtime = new_runtime(&secret, &policy);
    let resumed = runtime
        .resume(&reopened, unix_now())
        .await
        .unwrap()
        .expect("partial publication should resume");
    assert_eq!(resumed.status, RelayListPublicationOutcomeStatus::Complete);
    assert_eq!(resumed.attempted_relays, [format!("{second_url}/")]);
    runtime.shutdown().await.unwrap();
    second.await.unwrap();

    let observed = seen_events.lock().unwrap();
    assert_eq!(observed.len(), 3);
    assert!(observed.iter().all(|event_id| event_id == &event.id));
}

#[tokio::test]
async fn policy_drift_is_rejected_before_network_or_persistence() {
    let secret = [172; 32];
    let policy = policy("wss://one.example", "wss://two.example");
    let runtime = new_runtime(&secret, &policy);
    let now = unix_now();
    let public_key = xonly_public_key(&secret).unwrap();
    let mismatched = UnsignedEvent::new(
        hex::encode(public_key),
        now,
        NIP65_RELAY_LIST_KIND,
        vec![vec!["r".into(), "wss://different.example".into()]],
        String::new(),
        &EventLimits::default(),
    )
    .unwrap()
    .sign_with_aux(&secret, &[173; 32], &EventLimits::default())
    .unwrap();
    let state = tempdir().unwrap();
    let store = SealedStore::open(state.path(), RequestedProvider::File)
        .await
        .unwrap();
    assert!(matches!(
        runtime.publish(&store, &mismatched, now).await,
        Err(RelayListPublicationRuntimeError::PolicyMismatch)
    ));
    assert!(runtime.resume(&store, now).await.unwrap().is_none());
    runtime.shutdown().await.unwrap();
}

fn new_runtime(
    secret: &[u8; 32],
    policy: &RelayListPublicationConfig,
) -> RelayListPublicationRuntime {
    RelayListPublicationRuntime::spawn(
        RelayAuthSigner::from_secret_key(*secret).unwrap(),
        policy,
        NostrRelayListPublisherConfig {
            relay_ready_timeout: Duration::from_secs(1),
            relay_settle_timeout: Duration::from_millis(25),
            service_shutdown_timeout: Duration::from_secs(2),
            connect_timeout: Duration::from_secs(1),
            response_timeout: Duration::from_secs(1),
            relay_shutdown_timeout: Duration::from_secs(1),
            ..NostrRelayListPublisherConfig::default()
        },
    )
    .unwrap()
}

fn policy(first: &str, second: &str) -> RelayListPublicationConfig {
    RelayListPublicationConfig {
        relays: vec![
            RelayListPublicationRelayConfig {
                url: first.into(),
                read: true,
                write: true,
            },
            RelayListPublicationRelayConfig {
                url: second.into(),
                read: true,
                write: true,
            },
        ],
        required_acknowledgements: 2,
    }
}

async fn serve_once(listener: TcpListener, accept: bool, seen: Arc<std::sync::Mutex<Vec<String>>>) {
    let (stream, _) = listener.accept().await.unwrap();
    serve_connection(stream, accept, seen).await;
}

async fn serve_twice(listener: TcpListener, seen: Arc<std::sync::Mutex<Vec<String>>>) {
    let (first, _) = listener.accept().await.unwrap();
    serve_connection(first, false, Arc::clone(&seen)).await;
    let (second, _) = listener.accept().await.unwrap();
    serve_connection(second, true, seen).await;
}

async fn serve_connection(
    stream: TcpStream,
    accept: bool,
    seen: Arc<std::sync::Mutex<Vec<String>>>,
) {
    let mut socket = accept_async(stream).await.unwrap();
    let publication = next_json(&mut socket).await;
    assert_eq!(publication[0], "EVENT");
    let event: SignedEvent = serde_json::from_value(publication[1].clone()).unwrap();
    event
        .verify(unix_now() + 1, &EventLimits::default())
        .unwrap();
    seen.lock().unwrap().push(event.id.clone());
    socket
        .send(Message::Text(
            json!([
                "OK",
                event.id,
                accept,
                if accept { "stored" } else { "blocked" }
            ])
            .to_string()
            .into(),
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
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs()
}
