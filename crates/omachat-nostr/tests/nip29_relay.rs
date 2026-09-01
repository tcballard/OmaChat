use futures_util::{SinkExt, StreamExt};
use omachat_nostr::{
    event::{EventLimits, SignedEvent, xonly_public_key},
    nip11::{
        HttpRelayInformationFetcher, RelayInformation, RelayInformationError,
        RelayInformationLimits, RelayInformationSource,
    },
    nip29::{GroupUserEvent, group_message},
    nip29_relay::{
        ROOM_SUBSCRIPTION_ID, RelayIdentityObservation, RoomCoordinate, RoomIdentityError,
        RoomSubscriptionError, RoomSubscriptionSink, RoomSubscriptionSync, RoomSubscriptions,
        TrustedRelayIdentities, normalize_relay_url, room_subscription_filters,
    },
    pool::{RelayPool, RelayPoolConfig},
    relay::{RelayConfig, RelayError, RelayNotification, RelayRoute},
};
use serde_json::{Value, json};
use std::{
    collections::BTreeSet,
    future::Future,
    time::{Duration, SystemTime, UNIX_EPOCH},
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
};
use tokio_tungstenite::{WebSocketStream, accept_async, tungstenite::Message};

const RELAY_SECRET: [u8; 32] = [5; 32];
const OTHER_RELAY_SECRET: [u8; 32] = [11; 32];
const AGENT_SECRET: [u8; 32] = [9; 32];
const NOW: u64 = 1_800_000_000;

fn pubkey(secret: &[u8; 32]) -> String {
    hex::encode(xonly_public_key(secret).expect("valid key"))
}

fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("clock")
        .as_secs()
}

fn limits() -> RelayInformationLimits {
    RelayInformationLimits::default()
}

fn information(pubkey: Option<&str>) -> RelayInformation {
    let document = json!({
        "name": "OmaChat bootstrap relay",
        "pubkey": pubkey.unwrap_or(""),
        "supported_nips": [1, 11, 29, 42],
        "software": "https://github.com/0ceanslim/grain",
        "version": "v0.7.1",
        "limitation": { "auth_required": true, "max_subscriptions": 10 }
    });
    RelayInformation::from_json(document.to_string().as_bytes(), &limits()).expect("document")
}

#[test]
fn nip11_documents_parse_strictly() {
    let relay = pubkey(&RELAY_SECRET);
    let parsed = information(Some(&relay));
    assert_eq!(parsed.pubkey(), Some(relay.as_str()));
    assert_eq!(parsed.name(), Some("OmaChat bootstrap relay"));
    assert_eq!(parsed.supported_nips(), [1, 11, 29, 42]);
    assert!(parsed.supports_nip(29));
    assert!(!parsed.supports_nip(65));
    assert_eq!(parsed.auth_required(), Some(true));
    assert_eq!(parsed.max_subscriptions(), Some(10));
    assert_eq!(parsed.version(), Some("v0.7.1"));

    // A fresh Grain deployment ships an empty pubkey: that is "no identity".
    assert_eq!(information(None).pubkey(), None);
    let minimal = RelayInformation::from_json(b"{}", &limits()).expect("empty object");
    assert_eq!(minimal.pubkey(), None);
    assert!(minimal.supported_nips().is_empty());

    let parse =
        |document: Value| RelayInformation::from_json(document.to_string().as_bytes(), &limits());
    assert_eq!(
        parse(json!({"pubkey": relay.to_uppercase()})).err(),
        Some(RelayInformationError::InvalidPublicKey)
    );
    assert_eq!(
        parse(json!({"pubkey": "npub1notthis"})).err(),
        Some(RelayInformationError::InvalidPublicKey)
    );
    assert_eq!(
        parse(json!({"pubkey": 42})).err(),
        Some(RelayInformationError::InvalidField("pubkey"))
    );
    assert_eq!(
        parse(json!({"supported_nips": ["29"]})).err(),
        Some(RelayInformationError::InvalidField("supported_nips"))
    );
    assert_eq!(
        parse(json!({"limitation": {"auth_required": "yes"}})).err(),
        Some(RelayInformationError::InvalidField("auth_required"))
    );
    assert_eq!(
        parse(json!([1, 2])).err(),
        Some(RelayInformationError::NotAnObject)
    );
    assert_eq!(
        RelayInformation::from_json(b"{", &limits()).err(),
        Some(RelayInformationError::MalformedJson)
    );
    let tight = RelayInformationLimits {
        max_document_bytes: 8,
        ..limits()
    };
    assert!(matches!(
        RelayInformation::from_json(b"{\"name\":\"too long\"}", &tight),
        Err(RelayInformationError::DocumentTooLarge { .. })
    ));
}

async fn serve_http_once(listener: TcpListener, response: Vec<u8>) -> String {
    let (mut stream, _) = listener.accept().await.expect("accept");
    let mut request = Vec::new();
    let mut chunk = [0_u8; 1024];
    loop {
        let read = stream.read(&mut chunk).await.expect("read");
        request.extend_from_slice(&chunk[..read]);
        if read == 0 || request.windows(4).any(|window| window == b"\r\n\r\n") {
            break;
        }
    }
    stream.write_all(&response).await.expect("write");
    stream.shutdown().await.expect("shutdown");
    String::from_utf8(request).expect("utf8 request")
}

fn fetcher() -> HttpRelayInformationFetcher {
    HttpRelayInformationFetcher::new(RelayRoute::Direct, Duration::from_secs(2), limits())
}

#[tokio::test]
async fn nip11_fetch_discovers_relay_identity_over_http() {
    let relay = pubkey(&RELAY_SECRET);
    let body = json!({"pubkey": relay, "supported_nips": [29]}).to_string();

    // Content-Length framing.
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let url = format!("ws://{}/", listener.local_addr().expect("addr"));
    let response = format!(
        "HTTP/1.1 200 OK\r\nContent-Type: application/nostr+json\r\nContent-Length: {}\r\n\r\n{body}",
        body.len()
    );
    let server = tokio::spawn(serve_http_once(listener, response.into_bytes()));
    let fetched = fetcher().fetch(&url).await.expect("fetched");
    assert_eq!(fetched.pubkey(), Some(relay.as_str()));
    let request = server.await.expect("server");
    assert!(request.starts_with("GET / HTTP/1.1\r\n"));
    assert!(request.contains("Accept: application/nostr+json\r\n"));
    assert!(request.contains("Connection: close\r\n"));

    // Chunked framing.
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let url = format!("ws://{}", listener.local_addr().expect("addr"));
    let (head, tail) = body.split_at(7);
    let response = format!(
        "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n{:x}\r\n{head}\r\n{:x}\r\n{tail}\r\n0\r\n\r\n",
        head.len(),
        tail.len()
    );
    let server = tokio::spawn(serve_http_once(listener, response.into_bytes()));
    let fetched = fetcher().fetch(&url).await.expect("fetched chunked");
    assert_eq!(fetched.pubkey(), Some(relay.as_str()));
    server.await.expect("server");

    // Unframed body terminated by close.
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let url = format!("ws://{}", listener.local_addr().expect("addr"));
    let response = format!("HTTP/1.0 200 OK\r\n\r\n{body}");
    let server = tokio::spawn(serve_http_once(listener, response.into_bytes()));
    assert_eq!(
        fetcher().fetch(&url).await.expect("unframed").pubkey(),
        Some(relay.as_str())
    );
    server.await.expect("server");

    // Non-200 responses and oversized documents fail closed.
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let url = format!("ws://{}", listener.local_addr().expect("addr"));
    let server = tokio::spawn(serve_http_once(
        listener,
        b"HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\n\r\n".to_vec(),
    ));
    assert_eq!(
        fetcher().fetch(&url).await.err(),
        Some(RelayInformationError::HttpStatus(404))
    );
    server.await.expect("server");

    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let url = format!("ws://{}", listener.local_addr().expect("addr"));
    let huge = "x".repeat(limits().max_document_bytes + 1);
    let response = format!(
        "HTTP/1.1 200 OK\r\nContent-Length: {}\r\n\r\n{huge}",
        huge.len()
    );
    let server = tokio::spawn(serve_http_once(listener, response.into_bytes()));
    assert_eq!(
        fetcher().fetch(&url).await.err(),
        Some(RelayInformationError::ResponseTooLarge)
    );
    server.await.expect("server");

    assert_eq!(
        fetcher().fetch("ftp://relay.example/").await.err(),
        Some(RelayInformationError::InvalidUrl)
    );
}

#[test]
fn missing_identity_fails_closed_where_binding_is_required() {
    let mut trusted = TrustedRelayIdentities::new();
    assert_eq!(
        trusted.observe("wss://relay.example", &information(None), NOW),
        Err(RoomIdentityError::MissingRelayIdentity {
            url: "wss://relay.example".to_owned()
        })
    );
    assert!(trusted.is_empty());
    assert_eq!(
        trusted.coordinate("wss://relay.example", "omarchy"),
        Err(RoomIdentityError::RelayNotBound {
            url: "wss://relay.example".to_owned()
        })
    );
    assert_eq!(
        trusted.relay_pubkey("http://relay.example"),
        Err(RoomIdentityError::InvalidRelayUrl)
    );
    assert_eq!(
        RoomSubscriptions::new("relay".to_owned(), None).err(),
        Some(RoomIdentityError::InvalidRelayIdentity)
    );
    assert_eq!(
        RoomCoordinate::new(pubkey(&RELAY_SECRET), String::new()).err(),
        Some(RoomIdentityError::EmptyGroupId)
    );
}

#[test]
fn relay_key_mismatch_is_a_fork_warning_with_evidence() {
    let relay = pubkey(&RELAY_SECRET);
    let other = pubkey(&OTHER_RELAY_SECRET);
    let mut trusted = TrustedRelayIdentities::new();
    assert_eq!(
        trusted
            .observe(
                "wss://relay.example/",
                &information(Some(&relay)),
                NOW - 100
            )
            .expect("bind"),
        RelayIdentityObservation::Bound
    );
    assert_eq!(
        trusted
            .observe("wss://relay.example", &information(Some(&relay)), NOW - 50)
            .expect("confirm"),
        RelayIdentityObservation::Confirmed
    );

    let Err(RoomIdentityError::IdentityConflict(conflict)) =
        trusted.observe("wss://relay.example", &information(Some(&other)), NOW)
    else {
        panic!("a different key must conflict");
    };
    assert_eq!(conflict.url, "wss://relay.example");
    assert_eq!(conflict.trusted_pubkey, relay);
    assert_eq!(conflict.presented_pubkey, other);
    assert_eq!(conflict.first_verified_at, NOW - 100);
    assert_eq!(conflict.last_verified_at, NOW - 50);
    assert_eq!(conflict.observed_at, NOW);
    assert_eq!(conflict.presented_version.as_deref(), Some("v0.7.1"));
    let message = conflict.to_string();
    assert!(message.contains(&relay) && message.contains(&other));
    assert!(message.contains("replacement or fork"));

    // The trusted binding is untouched; the changed key is never adopted.
    let binding = trusted.binding("wss://relay.example").expect("binding");
    assert_eq!(binding.relay_pubkey(), relay);
    assert_eq!(binding.last_verified_at(), NOW - 50);
    assert_eq!(
        trusted
            .coordinate("wss://relay.example", "omarchy")
            .expect("coordinate"),
        RoomCoordinate::new(relay, "omarchy".to_owned()).expect("coordinate")
    );
}

#[test]
fn room_identity_follows_the_relay_key_not_the_url() {
    let relay = pubkey(&RELAY_SECRET);
    let other = pubkey(&OTHER_RELAY_SECRET);
    let mut trusted = TrustedRelayIdentities::new();
    trusted
        .observe("wss://relay.example", &information(Some(&relay)), NOW)
        .expect("bind");
    trusted
        .observe(
            "wss://relay-2.example:443/",
            &information(Some(&relay)),
            NOW,
        )
        .expect("bind second url");
    trusted
        .observe("wss://impostor.example", &information(Some(&other)), NOW)
        .expect("bind other relay");

    // URL change, same verified key: the same room.
    let original = trusted
        .coordinate("wss://relay.example", "omarchy")
        .expect("coordinate");
    let moved = trusted
        .coordinate("wss://relay-2.example", "omarchy")
        .expect("coordinate");
    assert_eq!(original, moved);
    assert_eq!(
        trusted.urls_for(&relay),
        ["wss://relay-2.example", "wss://relay.example"]
    );

    // Same group ID, different relay key: a different room.
    let elsewhere = trusted
        .coordinate("wss://impostor.example", "omarchy")
        .expect("coordinate");
    assert_ne!(original, elsewhere);
    assert_eq!(elsewhere.relay_pubkey(), other);
    assert_eq!(elsewhere.group_id(), "omarchy");

    assert_eq!(
        normalize_relay_url("wss://Relay.Example:443/#frag").expect("normalized"),
        "wss://relay.example"
    );
    assert_eq!(
        normalize_relay_url("wss://relay.example/groups/").expect("normalized"),
        "wss://relay.example/groups"
    );
}

#[test]
fn subscription_filters_bind_state_kinds_to_the_relay_key() {
    let relay = pubkey(&RELAY_SECRET);
    assert!(room_subscription_filters(&relay, &BTreeSet::new(), None).is_empty());
    let rooms = ["omarchy", "linux"]
        .into_iter()
        .map(str::to_owned)
        .collect::<BTreeSet<_>>();
    let filters = room_subscription_filters(&relay, &rooms, Some(NOW));
    assert_eq!(filters.len(), 2);
    assert_eq!(filters[0]["#h"], json!(["linux", "omarchy"]));
    assert_eq!(filters[0]["since"], json!(NOW));
    assert!(
        filters[0]["kinds"]
            .as_array()
            .expect("kinds")
            .iter()
            .any(|kind| kind == 9005)
    );
    assert_eq!(filters[1]["authors"], json!([relay]));
    assert_eq!(filters[1]["#d"], json!(["linux", "omarchy"]));
    assert_eq!(
        filters[1]["kinds"],
        json!([39000, 39001, 39002, 39003, 39005])
    );
    assert!(filters[1].get("since").is_none());
}

#[derive(Default)]
struct FakeSink {
    calls: Vec<(String, Option<Vec<Value>>)>,
    reject_rooms_containing: Option<String>,
    reject_everything: bool,
    relays: usize,
}

impl FakeSink {
    fn new(relays: usize) -> Self {
        Self {
            relays,
            ..Self::default()
        }
    }

    fn results(&self, filters: Option<&[Value]>) -> Vec<Result<(), RelayError>> {
        let rejected = self.reject_everything
            || filters.is_some_and(|filters| {
                self.reject_rooms_containing.as_ref().is_some_and(|needle| {
                    filters
                        .iter()
                        .any(|filter| filter.to_string().contains(needle))
                })
            });
        (0..self.relays)
            .map(|relay_index| {
                if rejected && relay_index == self.relays - 1 {
                    Err(RelayError::InvalidConfig(
                        "test relay rejected the replacement",
                    ))
                } else {
                    Ok(())
                }
            })
            .collect()
    }
}

impl RoomSubscriptionSink for FakeSink {
    fn subscribe(
        &mut self,
        subscription_id: String,
        filters: Vec<Value>,
    ) -> impl Future<Output = Vec<Result<(), RelayError>>> + Send {
        let results = self.results(Some(&filters));
        self.calls.push((subscription_id, Some(filters)));
        async move { results }
    }

    fn close_subscription(
        &mut self,
        subscription_id: String,
    ) -> impl Future<Output = Vec<Result<(), RelayError>>> + Send {
        let results = self.results(None);
        self.calls.push((subscription_id, None));
        async move { results }
    }
}

#[tokio::test]
async fn join_and_leave_refresh_the_room_subscription() {
    let relay = pubkey(&RELAY_SECRET);
    let mut sink = FakeSink::new(2);
    let mut rooms = RoomSubscriptions::new(relay.clone(), Some(NOW)).expect("rooms");
    assert_eq!(
        rooms.sync(&mut sink).await.expect("nothing to do"),
        RoomSubscriptionSync::Unchanged
    );
    assert!(sink.calls.is_empty());

    assert!(rooms.join("omarchy").expect("join"));
    assert!(!rooms.join("omarchy").expect("idempotent join"));
    assert_eq!(
        rooms.sync(&mut sink).await.expect("subscribe"),
        RoomSubscriptionSync::Replaced { rooms: 1 }
    );
    assert!(rooms.join("linux").expect("join"));
    assert_eq!(
        rooms.sync(&mut sink).await.expect("replace"),
        RoomSubscriptionSync::Replaced { rooms: 2 }
    );
    assert_eq!(
        rooms.sync(&mut sink).await.expect("steady"),
        RoomSubscriptionSync::Unchanged
    );
    assert!(rooms.leave("omarchy"));
    assert!(!rooms.leave("omarchy"));
    assert_eq!(
        rooms.sync(&mut sink).await.expect("shrink"),
        RoomSubscriptionSync::Replaced { rooms: 1 }
    );
    assert!(rooms.leave("linux"));
    assert_eq!(
        rooms.sync(&mut sink).await.expect("close"),
        RoomSubscriptionSync::Closed
    );

    let ids = sink
        .calls
        .iter()
        .map(|(id, _)| id.as_str())
        .collect::<BTreeSet<_>>();
    assert_eq!(ids, BTreeSet::from([ROOM_SUBSCRIPTION_ID]));
    assert_eq!(sink.calls.len(), 4);
    assert_eq!(
        sink.calls[1].1.as_ref().expect("filters")[0]["#h"],
        json!(["linux", "omarchy"])
    );
    assert_eq!(
        sink.calls[2].1.as_ref().expect("filters")[0]["#h"],
        json!(["linux"])
    );
    assert!(sink.calls[3].1.is_none());
    assert!(rooms.applied_rooms().is_empty());
}

#[tokio::test]
async fn rejected_replacement_rolls_back_to_the_accepted_room_set() {
    let relay = pubkey(&RELAY_SECRET);
    let mut sink = FakeSink::new(2);
    let mut rooms = RoomSubscriptions::new(relay, None).expect("rooms");
    rooms.join("omarchy").expect("join");
    rooms.sync(&mut sink).await.expect("initial");

    sink.reject_rooms_containing = Some("forbidden".to_owned());
    rooms.join("forbidden").expect("join");
    let Err(RoomSubscriptionError::Rejected { rejections }) = rooms.sync(&mut sink).await else {
        panic!("replacement must be rejected");
    };
    assert_eq!(rejections.len(), 1);
    assert_eq!(rejections[0].0, 1);
    assert_eq!(
        rooms.desired_rooms(),
        &BTreeSet::from(["omarchy".to_owned()])
    );
    assert_eq!(rooms.applied_rooms(), rooms.desired_rooms());
    // The rejected replacement and the restoring re-subscribe were both issued.
    assert_eq!(sink.calls.len(), 3);
    assert_eq!(
        sink.calls[1].1.as_ref().expect("filters")[0]["#h"],
        json!(["forbidden", "omarchy"])
    );
    assert_eq!(
        sink.calls[2].1.as_ref().expect("filters")[0]["#h"],
        json!(["omarchy"])
    );
    assert_eq!(
        rooms.sync(&mut sink).await.expect("steady"),
        RoomSubscriptionSync::Unchanged
    );

    // When the restore itself fails, the caller learns both facts.
    sink.reject_everything = true;
    rooms.join("another").expect("join");
    assert!(matches!(
        rooms.sync(&mut sink).await,
        Err(RoomSubscriptionError::RollbackFailed { .. })
    ));
    assert_eq!(rooms.desired_rooms(), rooms.applied_rooms());

    // With nothing applied yet, a rejection leaves nothing subscribed.
    let mut fresh_sink = FakeSink::new(1);
    fresh_sink.reject_everything = true;
    let mut fresh = RoomSubscriptions::new(pubkey(&RELAY_SECRET), None).expect("rooms");
    fresh.join("omarchy").expect("join");
    assert!(fresh.sync(&mut fresh_sink).await.is_err());
    assert!(fresh.desired_rooms().is_empty());
    assert!(fresh_sink.calls[1].1.is_none());
}

fn relay_config(address: std::net::SocketAddr) -> RelayConfig {
    let mut config = RelayConfig::new(format!("ws://{address}/"), RelayRoute::Direct);
    config.ping_interval = Duration::from_secs(5);
    config.idle_timeout = Duration::from_secs(15);
    config.response_timeout = Duration::from_millis(500);
    config.reconnect_initial_delay = Duration::from_millis(10);
    config.reconnect_max_delay = Duration::from_millis(20);
    config
}

async fn next_json(socket: &mut WebSocketStream<TcpStream>) -> Value {
    loop {
        match socket.next().await.expect("frame").expect("ok frame") {
            Message::Text(text) => return serde_json::from_str(&text).expect("json"),
            Message::Ping(payload) => socket.send(Message::Pong(payload)).await.expect("pong"),
            other => panic!("unexpected client message: {other:?}"),
        }
    }
}

async fn wait_connected(pool: &mut RelayPool, count: usize) {
    let mut connected = 0;
    tokio::time::timeout(Duration::from_secs(2), async {
        while connected < count {
            if matches!(
                pool.next_notification()
                    .await
                    .expect("notification")
                    .notification,
                RelayNotification::Connected
            ) {
                connected += 1;
            }
        }
    })
    .await
    .expect("connected in time");
}

async fn finish_on_close(mut socket: WebSocketStream<TcpStream>) {
    while let Some(Ok(message)) = socket.next().await {
        if matches!(message, Message::Close(_)) {
            break;
        }
    }
}

fn room_event(secret: &[u8; 32], group: &str, content: &str) -> SignedEvent {
    let limits = EventLimits::default();
    group_message(
        pubkey(secret),
        unix_now(),
        group,
        content.to_owned(),
        &[],
        &limits,
    )
    .expect("message")
    .sign_with_aux(secret, &[3; 32], &limits)
    .expect("signed")
}

/// Accepts twice: the first session is dropped after the REQ arrives, the
/// second session records the replayed REQ.
async fn reconnecting_relay(listener: TcpListener) -> (Value, Value) {
    let (stream, _) = listener.accept().await.expect("accept");
    let mut socket = accept_async(stream).await.expect("handshake");
    let first = next_json(&mut socket).await;
    drop(socket);
    let (stream, _) = listener.accept().await.expect("accept again");
    let mut socket = accept_async(stream).await.expect("handshake again");
    let second = next_json(&mut socket).await;
    socket
        .send(Message::Text(json!(["EOSE", second[1]]).to_string().into()))
        .await
        .expect("eose");
    finish_on_close(socket).await;
    (first, second)
}

#[tokio::test]
async fn reconnect_restores_every_room_subscription() {
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let config = relay_config(listener.local_addr().expect("addr"));
    let server = tokio::spawn(reconnecting_relay(listener));
    let mut pool = RelayPool::spawn(vec![config], RelayPoolConfig::default()).expect("pool");
    wait_connected(&mut pool, 1).await;

    let mut rooms = RoomSubscriptions::new(pubkey(&RELAY_SECRET), None).expect("rooms");
    rooms.join("omarchy").expect("join");
    rooms.join("linux").expect("join");
    assert_eq!(
        rooms.sync(&mut pool).await.expect("subscribe"),
        RoomSubscriptionSync::Replaced { rooms: 2 }
    );

    // Drive the pool until the relay reconnects and replays, then EOSE arrives.
    tokio::time::timeout(Duration::from_secs(3), async {
        loop {
            if let RelayNotification::EndOfStoredEvents { subscription_id } = pool
                .next_notification()
                .await
                .expect("notification")
                .notification
            {
                assert_eq!(subscription_id, ROOM_SUBSCRIPTION_ID);
                break;
            }
        }
    })
    .await
    .expect("reconnect replay in time");

    for outcome in pool.shutdown().await {
        outcome.expect("shutdown");
    }
    let (first, second) = server.await.expect("server");
    assert_eq!(first[0], "REQ");
    assert_eq!(first[1], ROOM_SUBSCRIPTION_ID);
    assert_eq!(second, first, "replayed subscription must be identical");
    assert_eq!(first[2]["#h"], json!(["linux", "omarchy"]));
    assert_eq!(first[3]["authors"], json!([pubkey(&RELAY_SECRET)]));
}

async fn delivering_relay(
    listener: TcpListener,
    events: Vec<SignedEvent>,
    forgery: Option<SignedEvent>,
) {
    let (stream, _) = listener.accept().await.expect("accept");
    let mut socket = accept_async(stream).await.expect("handshake");
    let request = next_json(&mut socket).await;
    assert_eq!(request[0], "REQ");
    for event in events {
        socket
            .send(Message::Text(
                json!(["EVENT", ROOM_SUBSCRIPTION_ID, event])
                    .to_string()
                    .into(),
            ))
            .await
            .expect("event");
    }
    socket
        .send(Message::Text(
            json!(["EOSE", ROOM_SUBSCRIPTION_ID]).to_string().into(),
        ))
        .await
        .expect("eose");
    if let Some(forgery) = forgery {
        socket
            .send(Message::Text(
                json!(["EVENT", ROOM_SUBSCRIPTION_ID, forgery])
                    .to_string()
                    .into(),
            ))
            .await
            .expect("forged event");
        // The client drops a relay that sends an unverifiable event; do not
        // wait for a graceful close that will never come.
        return;
    }
    finish_on_close(socket).await;
}

#[tokio::test]
async fn duplicate_delivery_is_processed_once_and_forgeries_never_surface() {
    let genuine = room_event(&AGENT_SECRET, "omarchy", "hello");
    let mut forged = room_event(&AGENT_SECRET, "omarchy", "forged");
    forged.content = "edited after signing".to_owned();

    let first = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let second = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let configs = vec![
        relay_config(first.local_addr().expect("addr")),
        relay_config(second.local_addr().expect("addr")),
    ];
    // Relay 0 is the "default" relay and also the one that tries a forgery.
    let first_server = tokio::spawn(delivering_relay(first, vec![genuine.clone()], Some(forged)));
    let second_server = tokio::spawn(delivering_relay(second, vec![genuine.clone()], None));
    let mut pool = RelayPool::spawn(configs, RelayPoolConfig::default()).expect("pool");
    wait_connected(&mut pool, 2).await;

    let mut rooms = RoomSubscriptions::new(pubkey(&RELAY_SECRET), None).expect("rooms");
    rooms.join("omarchy").expect("join");
    rooms.sync(&mut pool).await.expect("subscribe");

    let mut delivered = Vec::new();
    let mut eose = 0;
    let mut dropped_default_relay = false;
    tokio::time::timeout(Duration::from_secs(3), async {
        while eose < 2 || !dropped_default_relay {
            let notification = pool.next_notification().await.expect("notification");
            match notification.notification {
                RelayNotification::Event { event, .. } => delivered.push(event),
                RelayNotification::EndOfStoredEvents { .. } => eose += 1,
                RelayNotification::Disconnected if notification.relay_index == 0 => {
                    dropped_default_relay = true;
                }
                _ => {}
            }
        }
    })
    .await
    .expect("both relays finished and the forging relay was dropped");

    // One genuine event, delivered once across two relays; the forgery from
    // the default relay never surfaced as an event and cost it the session.
    assert_eq!(delivered.len(), 1);
    assert_eq!(delivered[0].id, genuine.id);
    let parsed = GroupUserEvent::verify(
        delivered[0].clone(),
        unix_now() + 5,
        &EventLimits::default(),
    )
    .expect("room event");
    assert_eq!(parsed.group_id(), "omarchy");
    assert_eq!(parsed.author(), pubkey(&AGENT_SECRET));

    for outcome in pool.shutdown().await {
        outcome.expect("shutdown");
    }
    first_server.await.expect("first");
    second_server.await.expect("second");
}
