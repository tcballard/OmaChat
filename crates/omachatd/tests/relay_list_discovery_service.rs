use std::time::{Duration, SystemTime, UNIX_EPOCH};

use futures_util::{SinkExt, StreamExt};
use omachat_nostr::{
    auth::RelayAuthSigner,
    discovery::{NIP65_RELAY_LIST_KIND, RelayDiscoveryLimits, RelayPreference},
    event::{EventLimits, SignedEvent, xonly_public_key},
    relay::{RelayConfig, RelayRoute},
    relay_list::create_nip65_relay_list_with_aux,
    relay_list_cache::{RelayListCacheLookup, RelayListCacheMutation},
    relay_list_discovery::RelayListDiscoveryConfig,
};
use omachat_store::{RequestedProvider, SealedStore};
use omachatd::{
    SealedRelayListCache, SealedRelayListCacheState, SealedRelayListDiscoveryService,
    SealedRelayListDiscoveryServiceError,
};
use serde_json::{Value, json};
use tempfile::tempdir;
use tokio::net::{TcpListener, TcpStream};
use tokio_tungstenite::{WebSocketStream, accept_async, tungstenite::Message};

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn public_relay_discovery_is_sealed_before_the_result_is_returned() {
    let now = unix_now();
    let participant_secret = [121; 32];
    let participant = xonly_public_key(&participant_secret).expect("participant public key");
    let event = relay_list(participant_secret, now - 1, "wss://external.example", 122);
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!("ws://{}", listener.local_addr().unwrap());
    let server = tokio::spawn(serve_public_query(
        listener,
        hex::encode(participant),
        vec![event.clone()],
    ));
    let directory = tempdir().expect("state directory");
    let store = SealedStore::open(directory.path(), RequestedProvider::File)
        .await
        .expect("open store");
    let service = service(&store);

    let result = service
        .discover_and_save(
            vec![relay_config(&url)],
            RelayAuthSigner::from_secret_key([123; 32]).unwrap(),
            &participant,
            now,
        )
        .await
        .expect("discover and save relay list");
    assert_eq!(result.event, event);
    assert_eq!(result.mutation, RelayListCacheMutation::Stored);
    assert_eq!(result.queried_relays, 1);
    assert_eq!(result.completed_relays, 1);
    server.await.unwrap();
    drop(service);
    drop(store);

    let reopened = SealedStore::open(directory.path(), RequestedProvider::File)
        .await
        .expect("reopen store");
    let SealedRelayListCacheState::Loaded(cache) = SealedRelayListCache::new(&reopened)
        .load(
            now,
            &EventLimits::default(),
            &RelayDiscoveryLimits::default(),
        )
        .expect("load sealed discovery")
    else {
        panic!("sealed discovery was missing after restart");
    };
    let RelayListCacheLookup::Fresh(record) = cache.lookup(&participant, now, 10) else {
        panic!("sealed discovery was not fresh");
    };
    assert_eq!(record.source_event(), &event);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn malicious_relay_cannot_persist_another_authors_list() {
    let now = unix_now();
    let expected_secret = [124; 32];
    let expected = xonly_public_key(&expected_secret).expect("expected public key");
    let forged = relay_list([125; 32], now - 1, "wss://attacker.example", 126);
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!("ws://{}", listener.local_addr().unwrap());
    let server = tokio::spawn(serve_public_query(
        listener,
        hex::encode(expected),
        vec![forged],
    ));
    let directory = tempdir().expect("state directory");
    let store = SealedStore::open(directory.path(), RequestedProvider::File)
        .await
        .expect("open store");
    let service = service(&store);

    assert!(matches!(
        service
            .discover_and_save(
                vec![relay_config(&url)],
                RelayAuthSigner::from_secret_key([127; 32]).unwrap(),
                &expected,
                now,
            )
            .await,
        Err(SealedRelayListDiscoveryServiceError::Discovery(_))
    ));
    server.await.unwrap();
    assert!(matches!(
        service.load_cache(now),
        Ok(SealedRelayListCacheState::Missing)
    ));
}

fn service(store: &SealedStore) -> SealedRelayListDiscoveryService<'_> {
    SealedRelayListDiscoveryService::new(
        store,
        EventLimits::default(),
        RelayDiscoveryLimits::default(),
        RelayListDiscoveryConfig {
            authentication_timeout: Duration::from_secs(2),
            challenge_settle_timeout: Duration::from_millis(25),
            query_timeout: Duration::from_secs(2),
            subscription_id: "sealed-nip65-discovery".into(),
            ..RelayListDiscoveryConfig::default()
        },
    )
}

fn relay_config(url: &str) -> RelayConfig {
    let mut config = RelayConfig::new(url.into(), RelayRoute::Direct);
    config.connect_timeout = Duration::from_secs(1);
    config.response_timeout = Duration::from_secs(1);
    config.shutdown_timeout = Duration::from_secs(1);
    config
}

fn relay_list(secret: [u8; 32], created_at: u64, url: &str, auxiliary: u8) -> SignedEvent {
    create_nip65_relay_list_with_aux(
        &secret,
        created_at,
        &[RelayPreference {
            url: url.into(),
            read: true,
            write: true,
        }],
        &[auxiliary; 32],
        &EventLimits::default(),
        &RelayDiscoveryLimits::default(),
    )
    .expect("signed relay list")
}

async fn serve_public_query(
    listener: TcpListener,
    expected_author: String,
    events: Vec<SignedEvent>,
) {
    let (stream, _) = listener.accept().await.unwrap();
    let mut socket = accept_async(stream).await.unwrap();
    let request = next_json(&mut socket).await;
    assert_eq!(request[0], "REQ");
    assert_eq!(request[2]["kinds"], json!([NIP65_RELAY_LIST_KIND]));
    assert_eq!(request[2]["authors"], json!([expected_author]));
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
        .expect("system time after Unix epoch")
        .as_secs()
}
