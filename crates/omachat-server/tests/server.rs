//! End-to-end tests against a real listener: WebSocket handshake, device
//! authentication, workspaces, channels, direct messages, receipts, limits
//! and restart persistence.

use ed25519_dalek::SigningKey;
use futures_util::{SinkExt, StreamExt};
use omachat_server::{
    HostLimits, HostReport, Registration, ServerIdentity, ServiceConfig, SessionLimits, Storage,
    StorageError,
    auth::{sign_device_challenge, verify_hello_signature},
    protocol::{MAX_FRAME_BYTES, MAX_TEXT_BYTES},
    run_host, spawn_service,
};
use serde_json::{Value, json};
use std::{collections::VecDeque, net::SocketAddr, path::Path, sync::Arc, time::Duration};
use tokio::{
    net::{TcpListener, TcpStream},
    sync::oneshot,
    task::JoinHandle,
    time::timeout,
};
use tokio_tungstenite::{WebSocketStream, client_async, tungstenite::Message};
use zeroize::Zeroizing;

const STORAGE_KEY: [u8; 32] = [42_u8; 32];
const SERVER_SEED: [u8; 32] = [7_u8; 32];

struct TestServer {
    address: SocketAddr,
    public_key: [u8; 32],
    stop: Option<oneshot::Sender<()>>,
    task: JoinHandle<HostReport>,
}

impl TestServer {
    async fn start(directory: &Path, registration: Registration, limits: HostLimits) -> Self {
        let storage =
            Storage::open(&directory.join("messages.db"), Zeroizing::new(STORAGE_KEY)).unwrap();
        let identity = Arc::new(ServerIdentity::from_seed(&SERVER_SEED));
        let public_key = identity.public_key();
        let service = spawn_service(
            storage,
            ServiceConfig {
                registration,
                server_public_key: public_key,
            },
        )
        .unwrap();
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let (stop, stopped) = oneshot::channel();
        let task = tokio::spawn(async move {
            run_host(listener, service, identity, limits, async move {
                let _ = stopped.await;
            })
            .await
            .unwrap()
        });
        Self {
            address,
            public_key,
            stop: Some(stop),
            task,
        }
    }

    async fn stop(mut self) -> HostReport {
        let _ = self.stop.take().unwrap().send(());
        self.task.await.unwrap()
    }
}

fn fast_limits() -> HostLimits {
    HostLimits {
        session: SessionLimits {
            requests_per_second: 1000,
            request_burst: 1000,
            ..SessionLimits::default()
        },
        ..HostLimits::default()
    }
}

struct Client {
    socket: WebSocketStream<TcpStream>,
    next_id: u64,
    events: VecDeque<Value>,
}

impl Client {
    async fn connect(address: SocketAddr) -> Self {
        let stream = TcpStream::connect(address).await.unwrap();
        let (socket, _) = client_async(format!("ws://{address}/"), stream)
            .await
            .unwrap();
        Self {
            socket,
            next_id: 1,
            events: VecDeque::new(),
        }
    }

    async fn send_raw(&mut self, frame: String) {
        self.socket.send(Message::Text(frame.into())).await.unwrap();
    }

    /// Next frame from the server, or `None` when the connection closed.
    async fn next_frame(&mut self) -> Option<Value> {
        loop {
            let message = timeout(Duration::from_secs(5), self.socket.next())
                .await
                .expect("server answered within five seconds")?;
            match message {
                Ok(Message::Text(text)) => {
                    return Some(serde_json::from_str(text.as_str()).unwrap());
                }
                Ok(Message::Close(_)) | Err(_) => return None,
                Ok(_) => {}
            }
        }
    }

    async fn call(&mut self, method: &str, params: Value) -> Value {
        let id = self.next_id.to_string();
        self.next_id += 1;
        let mut request = json!({"version": 1, "id": id, "method": method});
        if !params.is_null() {
            request["params"] = params;
        }
        self.send_raw(request.to_string()).await;
        loop {
            let frame = self.next_frame().await.expect("connection stayed open");
            if frame.get("event").is_some() {
                self.events.push_back(frame);
                continue;
            }
            assert_eq!(
                frame["id"],
                Value::String(id.clone()),
                "responses arrive in order"
            );
            return frame;
        }
    }

    async fn ok(&mut self, method: &str, params: Value) -> Value {
        let response = self.call(method, params).await;
        assert_eq!(
            response["ok"],
            Value::Bool(true),
            "{method} failed: {response}"
        );
        response["result"].clone()
    }

    async fn err(&mut self, method: &str, params: Value) -> String {
        let response = self.call(method, params).await;
        assert_eq!(
            response["ok"],
            Value::Bool(false),
            "{method} unexpectedly succeeded: {response}"
        );
        response["error"]["code"].as_str().unwrap().to_owned()
    }

    async fn event(&mut self) -> Value {
        if let Some(event) = self.events.pop_front() {
            return event;
        }
        let frame = self.next_frame().await.expect("connection stayed open");
        assert!(
            frame.get("event").is_some(),
            "unexpected response while waiting for an event: {frame}"
        );
        frame
    }

    async fn no_event(&mut self) {
        assert!(
            self.events.is_empty(),
            "unexpected buffered event: {:?}",
            self.events
        );
        let waited = timeout(Duration::from_millis(300), self.socket.next()).await;
        assert!(waited.is_err(), "unexpected frame: {waited:?}");
    }

    async fn hello(&mut self, server_public_key: &[u8; 32], seed: &[u8; 32]) -> [u8; 32] {
        let device_public_key = SigningKey::from_bytes(seed).verifying_key().to_bytes();
        let hello = self
            .ok(
                "hello",
                json!({
                    "minimum_version": 1,
                    "maximum_version": 1,
                    "device_public_key": hex::encode(device_public_key),
                }),
            )
            .await;
        let challenge: [u8; 32] = hex::decode(hello["challenge"].as_str().unwrap())
            .unwrap()
            .try_into()
            .unwrap();
        let signature: [u8; 64] = hex::decode(hello["server_signature"].as_str().unwrap())
            .unwrap()
            .try_into()
            .unwrap();
        assert_eq!(
            hello["server_public_key"],
            json!(hex::encode(server_public_key))
        );
        verify_hello_signature(
            server_public_key,
            &challenge,
            &device_public_key,
            &signature,
        )
        .expect("server proves its identity over the challenge");
        challenge
    }

    async fn login(
        server: &TestServer,
        seed: &[u8; 32],
        display_name: Option<&str>,
        invite: Option<&str>,
    ) -> (Self, Value) {
        let mut client = Self::connect(server.address).await;
        let challenge = client.hello(&server.public_key, seed).await;
        let signature = sign_device_challenge(seed, &server.public_key, &challenge);
        let mut params = json!({"signature": hex::encode(signature)});
        if let Some(name) = display_name {
            params["display_name"] = json!(name);
        }
        if let Some(code) = invite {
            params["invite_code"] = json!(code);
        }
        let result = client.ok("authenticate", params).await;
        (client, result)
    }
}

fn text(value: &Value, key: &str) -> String {
    value[key].as_str().unwrap().to_owned()
}

#[tokio::test]
async fn registration_authentication_and_status() {
    let directory = tempfile::tempdir().unwrap();
    let server = TestServer::start(directory.path(), Registration::Open, fast_limits()).await;
    let seed = [1_u8; 32];
    let (mut ada, first) = Client::login(&server, &seed, Some("Ada"), None).await;
    assert_eq!(first["new_account"], Value::Bool(true));
    assert_eq!(first["display_name"], json!("Ada"));
    let status = ada.ok("status", Value::Null).await;
    assert_eq!(status["account_id"], first["account_id"]);
    assert_eq!(
        status["server_public_key"],
        json!(hex::encode(server.public_key))
    );
    assert_eq!(status["registration"], json!("open"));
    assert_eq!(
        ada.err(
            "hello",
            json!({"minimum_version": 1, "maximum_version": 1, "device_public_key": "00"})
        )
        .await,
        "already-authenticated"
    );
    drop(ada);

    let (mut again, second) = Client::login(&server, &seed, None, None).await;
    assert_eq!(second["new_account"], Value::Bool(false));
    assert_eq!(second["account_id"], first["account_id"]);
    assert_eq!(
        second["display_name"],
        json!("Ada"),
        "display name is not overwritten by a later login"
    );
    let unnamed_seed = [2_u8; 32];
    let (_, unnamed) = Client::login(&server, &unnamed_seed, None, None).await;
    assert!(text(&unnamed, "display_name").starts_with("user-"));
    drop(again.ok("status", Value::Null).await);
    let report = server.stop().await;
    assert!(report.authenticated_sessions >= 3);
}

#[tokio::test]
async fn bad_signatures_wrong_order_and_bad_versions_are_refused() {
    let directory = tempfile::tempdir().unwrap();
    let server = TestServer::start(directory.path(), Registration::Open, fast_limits()).await;

    let mut forged = Client::connect(server.address).await;
    let challenge = forged.hello(&server.public_key, &[1_u8; 32]).await;
    let other_signature = sign_device_challenge(&[9_u8; 32], &server.public_key, &challenge);
    assert_eq!(
        forged
            .err(
                "authenticate",
                json!({"signature": hex::encode(other_signature)})
            )
            .await,
        "invalid-signature"
    );
    assert!(
        forged.next_frame().await.is_none(),
        "connection closes after a failed authentication"
    );

    let mut eager = Client::connect(server.address).await;
    assert_eq!(eager.err("status", Value::Null).await, "not-authenticated");
    assert!(eager.next_frame().await.is_none());

    let mut old = Client::connect(server.address).await;
    assert_eq!(
        old.err("hello", json!({"minimum_version": 2, "maximum_version": 3, "device_public_key": hex::encode([1_u8; 32])})).await,
        "unsupported-version"
    );
    assert!(old.next_frame().await.is_none());

    let mut garbage = Client::connect(server.address).await;
    garbage.send_raw("this is not json".into()).await;
    let frame = garbage.next_frame().await.unwrap();
    assert_eq!(frame["error"]["code"], json!("invalid-request"));
    assert!(garbage.next_frame().await.is_none());

    let mut replay = Client::connect(server.address).await;
    let first_challenge = replay.hello(&server.public_key, &[1_u8; 32]).await;
    let mut second = Client::connect(server.address).await;
    let second_challenge = second.hello(&server.public_key, &[1_u8; 32]).await;
    assert_ne!(
        first_challenge, second_challenge,
        "challenges are fresh per connection"
    );
    let stale = sign_device_challenge(&[1_u8; 32], &server.public_key, &first_challenge);
    assert_eq!(
        second
            .err("authenticate", json!({"signature": hex::encode(stale)}))
            .await,
        "invalid-signature"
    );
    drop(replay);
    server.stop().await;
}

#[tokio::test]
async fn invite_and_closed_registration_modes() {
    let directory = tempfile::tempdir().unwrap();
    let invites = Registration::invite_codes(["golden-ticket".to_owned()]).unwrap();
    let server = TestServer::start(directory.path(), invites, fast_limits()).await;
    let mut uninvited = Client::connect(server.address).await;
    let challenge = uninvited.hello(&server.public_key, &[1_u8; 32]).await;
    let signature = sign_device_challenge(&[1_u8; 32], &server.public_key, &challenge);
    assert_eq!(
        uninvited
            .err(
                "authenticate",
                json!({"signature": hex::encode(signature), "invite_code": "nope"})
            )
            .await,
        "invalid-invite"
    );
    let (_ada, result) =
        Client::login(&server, &[1_u8; 32], Some("Ada"), Some("golden-ticket")).await;
    assert_eq!(result["new_account"], Value::Bool(true));
    server.stop().await;

    let server = TestServer::start(directory.path(), Registration::Closed, fast_limits()).await;
    let (_ada, again) = Client::login(&server, &[1_u8; 32], None, None).await;
    assert_eq!(again["new_account"], Value::Bool(false));
    let mut stranger = Client::connect(server.address).await;
    let challenge = stranger.hello(&server.public_key, &[2_u8; 32]).await;
    let signature = sign_device_challenge(&[2_u8; 32], &server.public_key, &challenge);
    assert_eq!(
        stranger
            .err("authenticate", json!({"signature": hex::encode(signature)}))
            .await,
        "registration-closed"
    );
    server.stop().await;
}

#[tokio::test]
async fn workspace_channel_and_direct_message_flow() {
    let directory = tempfile::tempdir().unwrap();
    let server = TestServer::start(directory.path(), Registration::Open, fast_limits()).await;
    let (mut ada, ada_account) = Client::login(&server, &[1_u8; 32], Some("Ada"), None).await;
    let (mut bob, bob_account) = Client::login(&server, &[2_u8; 32], Some("Bob"), None).await;
    let ada_id = text(&ada_account, "account_id");
    let bob_id = text(&bob_account, "account_id");

    ada.ok("claim-handle", json!({"handle": "@ada"})).await;
    bob.ok("claim-handle", json!({"handle": "bob"})).await;
    assert_eq!(
        bob.err("claim-handle", json!({"handle": "ada"})).await,
        "handle-already-set"
    );
    let (mut carol, _) = Client::login(&server, &[3_u8; 32], Some("Carol"), None).await;
    assert_eq!(
        carol.err("claim-handle", json!({"handle": "ada"})).await,
        "handle-taken"
    );
    assert_eq!(
        carol.err("claim-handle", json!({"handle": "Ada!"})).await,
        "invalid-handle"
    );
    carol.ok("claim-handle", json!({"handle": "carol"})).await;
    let resolved = ada.ok("resolve-handle", json!({"handle": "bob"})).await;
    assert_eq!(resolved["account_id"], json!(bob_id));
    assert_eq!(
        ada.err("resolve-handle", json!({"handle": "nobody"})).await,
        "not-found"
    );

    let workspace = text(
        &ada.ok("create-workspace", json!({"name": "Omarchy"})).await,
        "workspace_id",
    );
    let general = text(
        &ada.ok(
            "create-channel",
            json!({"workspace_id": workspace, "name": "general"}),
        )
        .await,
        "conversation_id",
    );
    assert_eq!(
        ada.err(
            "create-channel",
            json!({"workspace_id": workspace, "name": "general"})
        )
        .await,
        "name-taken"
    );
    assert_eq!(
        ada.err(
            "create-channel",
            json!({"workspace_id": workspace, "name": " padded"})
        )
        .await,
        "invalid-name"
    );
    let created = ada.event().await;
    assert_eq!(created["event"], json!("conversation"));
    assert_eq!(created["data"]["conversation_id"], json!(general));

    let added = ada
        .ok(
            "add-member",
            json!({"workspace_id": workspace, "handle": "bob"}),
        )
        .await;
    assert_eq!(added["channels_joined"], json!(1));
    let joined = bob.event().await;
    assert_eq!(joined["event"], json!("conversation"));
    assert_eq!(joined["data"]["name"], json!("general"));
    assert_eq!(joined["data"]["members"].as_array().unwrap().len(), 2);
    assert_eq!(
        bob.err(
            "create-channel",
            json!({"workspace_id": workspace, "name": "random"})
        )
        .await,
        "forbidden"
    );
    assert_eq!(
        bob.err(
            "add-member",
            json!({"workspace_id": workspace, "handle": "carol"})
        )
        .await,
        "forbidden"
    );
    assert_eq!(
        carol
            .err(
                "send",
                json!({"conversation_id": general, "client_id": "c1", "text": "hi"})
            )
            .await,
        "not-found"
    );
    assert_eq!(
        carol
            .err("history", json!({"conversation_id": general}))
            .await,
        "not-found"
    );

    let sent = ada
        .ok(
            "send",
            json!({"conversation_id": general, "client_id": "first", "text": "hello team"}),
        )
        .await;
    assert_eq!(sent["sequence"], json!(1));
    assert_eq!(sent["duplicate"], Value::Bool(false));
    let own_copy = ada.event().await;
    assert_eq!(own_copy["event"], json!("message"));
    assert_eq!(own_copy["data"]["sequence"], json!(1));
    let received = bob.event().await;
    assert_eq!(received["event"], json!("message"));
    assert_eq!(received["data"]["text"], json!("hello team"));
    assert_eq!(received["data"]["sender_account_id"], json!(ada_id));

    let resent = ada
        .ok(
            "send",
            json!({"conversation_id": general, "client_id": "first", "text": "hello team"}),
        )
        .await;
    assert_eq!(
        resent["sequence"],
        json!(1),
        "retrying with the same client_id never duplicates"
    );
    assert_eq!(resent["duplicate"], Value::Bool(true));
    assert_eq!(resent["id"], sent["id"]);
    bob.no_event().await;

    let read = bob
        .ok(
            "mark-read",
            json!({"conversation_id": general, "sequence": 1}),
        )
        .await;
    assert_eq!(read["read_sequence"], json!(1));
    let receipt = ada.event().await;
    assert_eq!(receipt["event"], json!("receipt"));
    assert_eq!(receipt["data"]["account_id"], json!(bob_id));
    assert_eq!(receipt["data"]["delivered_sequence"], json!(1));
    assert_eq!(bob.event().await["event"], json!("receipt"));
    assert_eq!(
        bob.err(
            "mark-read",
            json!({"conversation_id": general, "sequence": 5})
        )
        .await,
        "invalid-request"
    );

    for index in 2..=5 {
        bob.ok("send", json!({"conversation_id": general, "client_id": format!("b{index}"), "text": format!("reply {index}")})).await;
    }
    for expected in 2..=5 {
        assert_eq!(ada.event().await["data"]["sequence"], json!(expected));
        assert_eq!(
            bob.event().await["data"]["sequence"],
            json!(expected),
            "senders also receive their own copy"
        );
    }
    let page = ada
        .ok("history", json!({"conversation_id": general, "limit": 2}))
        .await;
    let sequences: Vec<u64> = page["messages"]
        .as_array()
        .unwrap()
        .iter()
        .map(|m| m["sequence"].as_u64().unwrap())
        .collect();
    assert_eq!(sequences, vec![4, 5]);
    let earlier = ada
        .ok(
            "history",
            json!({"conversation_id": general, "before_sequence": 4, "limit": 10}),
        )
        .await;
    let sequences: Vec<u64> = earlier["messages"]
        .as_array()
        .unwrap()
        .iter()
        .map(|m| m["sequence"].as_u64().unwrap())
        .collect();
    assert_eq!(sequences, vec![1, 2, 3]);
    assert_eq!(earlier["messages"][0]["text"], json!("hello team"));

    let listed = bob.ok("list-conversations", Value::Null).await;
    let conversations = listed["conversations"].as_array().unwrap();
    assert_eq!(conversations.len(), 1);
    assert_eq!(conversations[0]["last_sequence"], json!(5));
    assert_eq!(
        conversations[0]["read_sequence"],
        json!(5),
        "a sender's own messages count as read"
    );

    let dm = ada.ok("open-dm", json!({"handle": "bob"})).await;
    assert_eq!(dm["kind"], json!("dm"));
    let dm_id = text(&dm, "conversation_id");
    let opened = bob.event().await;
    assert_eq!(opened["event"], json!("conversation"));
    assert_eq!(opened["data"]["conversation_id"], json!(dm_id));
    let same = bob.ok("open-dm", json!({"handle": "ada"})).await;
    assert_eq!(same["conversation_id"], json!(dm_id));
    ada.no_event().await;
    assert_eq!(
        ada.err("open-dm", json!({"handle": "ada"})).await,
        "invalid-request"
    );
    assert_eq!(
        carol
            .err(
                "send",
                json!({"conversation_id": dm_id, "client_id": "x", "text": "intrude"})
            )
            .await,
        "not-found"
    );
    assert_eq!(
        ada.err(
            "send",
            json!({"conversation_id": dm_id, "client_id": "first", "text": "reuse"})
        )
        .await,
        "invalid-request",
        "a client_id cannot be reused for another conversation"
    );
    // Drain the remaining message events before shutdown to keep the test deterministic.
    server.stop().await;
}

#[tokio::test]
async fn limits_are_enforced() {
    let directory = tempfile::tempdir().unwrap();
    let limits = HostLimits {
        session: SessionLimits {
            requests_per_second: 1,
            request_burst: 3,
            idle_timeout: Duration::from_secs(3),
            unauthenticated_timeout: Duration::from_secs(1),
            ..SessionLimits::default()
        },
        max_connections: 3,
        max_connections_per_ip: 3,
        ..HostLimits::default()
    };
    let server = TestServer::start(directory.path(), Registration::Open, limits).await;
    let (mut ada, _) = Client::login(&server, &[1_u8; 32], Some("Ada"), None).await;
    // hello and authenticate are bounded by their own deadline, not the bucket.
    for _ in 0..3 {
        ada.ok("status", Value::Null).await;
    }
    assert_eq!(ada.err("status", Value::Null).await, "rate-limited");
    // One token refills per second; each request below waits for one.
    tokio::time::sleep(Duration::from_millis(1100)).await;
    let workspace = text(
        &ada.ok("create-workspace", json!({"name": "W"})).await,
        "workspace_id",
    );
    tokio::time::sleep(Duration::from_millis(1100)).await;
    let channel = text(
        &ada.ok(
            "create-channel",
            json!({"workspace_id": workspace, "name": "c"}),
        )
        .await,
        "conversation_id",
    );
    tokio::time::sleep(Duration::from_millis(1100)).await;
    let too_long = "x".repeat(MAX_TEXT_BYTES + 1);
    assert_eq!(
        ada.err(
            "send",
            json!({"conversation_id": channel, "client_id": "big", "text": too_long})
        )
        .await,
        "too-large"
    );
    tokio::time::sleep(Duration::from_millis(1100)).await;
    let oversized_frame = json!({"version": 1, "id": "f", "method": "send", "params": {"conversation_id": channel, "client_id": "huge", "text": "y".repeat(MAX_FRAME_BYTES)}}).to_string();
    ada.send_raw(oversized_frame).await;
    assert!(
        ada.next_frame().await.is_none(),
        "a frame over 16 KiB closes the connection"
    );

    let mut silent = Client::connect(server.address).await;
    assert!(
        silent.next_frame().await.is_none(),
        "unauthenticated connections are closed after the deadline"
    );

    let (mut idle, _) = Client::login(&server, &[2_u8; 32], None, None).await;
    let started = std::time::Instant::now();
    assert!(
        idle.next_frame().await.is_none(),
        "idle connections are closed"
    );
    assert!(started.elapsed() >= Duration::from_millis(2900));
    let report = server.stop().await;
    assert_eq!(report.rejected_global_limit, 0);
}

#[tokio::test]
async fn connection_limits_reject_excess_clients() {
    let directory = tempfile::tempdir().unwrap();
    let limits = HostLimits {
        max_connections: 2,
        max_connections_per_ip: 2,
        session: fast_limits().session,
        ..HostLimits::default()
    };
    let server = TestServer::start(directory.path(), Registration::Open, limits).await;
    let (_first, _) = Client::login(&server, &[1_u8; 32], None, None).await;
    let (_second, _) = Client::login(&server, &[2_u8; 32], None, None).await;
    let third = TcpStream::connect(server.address).await.unwrap();
    let handshake = timeout(
        Duration::from_secs(2),
        client_async(format!("ws://{}/", server.address), third),
    )
    .await;
    assert!(
        handshake.is_err() || handshake.unwrap().is_err(),
        "a third connection is dropped without a handshake"
    );
    let report = server.stop().await;
    assert_eq!(report.rejected_global_limit, 1);
}

#[tokio::test]
async fn state_survives_restart_and_content_is_sealed_at_rest() {
    let directory = tempfile::tempdir().unwrap();
    let server = TestServer::start(directory.path(), Registration::Open, fast_limits()).await;
    let (mut ada, _) = Client::login(&server, &[1_u8; 32], Some("Ada"), None).await;
    let (mut bob, _) = Client::login(&server, &[2_u8; 32], Some("Bob"), None).await;
    ada.ok("claim-handle", json!({"handle": "ada"})).await;
    bob.ok("claim-handle", json!({"handle": "bob"})).await;
    let dm = text(
        &ada.ok("open-dm", json!({"handle": "bob"})).await,
        "conversation_id",
    );
    ada.ok(
        "send",
        json!({"conversation_id": dm, "client_id": "s1", "text": "secret pineapple recipe"}),
    )
    .await;
    let report = server.stop().await;
    assert!(!report.forced_shutdown);

    let mut on_disk = Vec::new();
    for name in ["messages.db", "messages.db-wal"] {
        if let Ok(bytes) = std::fs::read(directory.path().join(name)) {
            on_disk.extend_from_slice(&bytes);
        }
    }
    assert!(!on_disk.is_empty());
    assert!(
        !on_disk.windows(9).any(|window| window == b"pineapple"),
        "message text must not be stored in the clear"
    );
    assert!(
        on_disk.windows(3).any(|window| window == b"ada"),
        "metadata such as handles is not hidden"
    );

    assert!(matches!(
        Storage::open(
            &directory.path().join("messages.db"),
            Zeroizing::new([1_u8; 32])
        ),
        Err(StorageError::WrongKey)
    ));

    let server = TestServer::start(directory.path(), Registration::Closed, fast_limits()).await;
    let (mut bob, again) = Client::login(&server, &[2_u8; 32], None, None).await;
    assert_eq!(again["handle"], json!("bob"));
    let history = bob.ok("history", json!({"conversation_id": dm})).await;
    assert_eq!(
        history["messages"][0]["text"],
        json!("secret pineapple recipe")
    );
    let listed = bob.ok("list-conversations", Value::Null).await;
    assert_eq!(listed["conversations"][0]["conversation_id"], json!(dm));
    server.stop().await;
}

#[tokio::test]
async fn shutdown_closes_clients_gracefully() {
    let directory = tempfile::tempdir().unwrap();
    let server = TestServer::start(directory.path(), Registration::Open, fast_limits()).await;
    let (mut ada, _) = Client::login(&server, &[1_u8; 32], None, None).await;
    let report = server.stop().await;
    assert!(ada.next_frame().await.is_none());
    assert_eq!(report.authenticated_sessions, 1);
    assert!(!report.forced_shutdown);
}
