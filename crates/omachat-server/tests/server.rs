use ed25519_dalek::{Signer, SigningKey};
use futures_util::{SinkExt, StreamExt};
use omachat_crypto::NostrSecret;
use omachat_proto::hosted::{nostr_bind_transcript, nostr_unbind_transcript};
use omachat_server::{
    HostLimits, HostReport, ServerIdentity, ServiceConfig, SessionLimits, Storage, StorageError,
    auth::{sign_device_challenge, verify_hello_signature},
    protocol::MAX_FRAME_BYTES,
    run_host, spawn_service,
};
use serde_json::{Value, json};
use std::time::{SystemTime, UNIX_EPOCH};
use std::{collections::VecDeque, net::SocketAddr, path::Path, sync::Arc, time::Duration};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
    sync::oneshot,
    task::JoinHandle,
    time::timeout,
};
use tokio_tungstenite::{
    WebSocketStream, client_async, client_async_with_config,
    tungstenite::{Message, protocol::WebSocketConfig},
};
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
    async fn start(directory: &Path, limits: HostLimits) -> Self {
        let storage =
            Storage::open(&directory.join("server.db"), Zeroizing::new(STORAGE_KEY)).unwrap();
        let identity = Arc::new(ServerIdentity::from_seed(&SERVER_SEED));
        let public_key = identity.public_key();
        let service = spawn_service(
            storage,
            ServiceConfig {
                server_public_key: public_key,
                nip05_relays: Vec::new(),
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
        shutdown_grace: Duration::from_secs(1),
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
        let mut config = WebSocketConfig::default();
        config.max_message_size = Some(MAX_FRAME_BYTES);
        config.max_frame_size = Some(MAX_FRAME_BYTES);
        let (socket, _) =
            client_async_with_config(format!("ws://{address}/"), stream, Some(config))
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

    async fn next_frame(&mut self) -> Option<Value> {
        loop {
            let message = timeout(Duration::from_secs(5), self.socket.next())
                .await
                .expect("server answered within five seconds")?;
            match message {
                Ok(Message::Text(text)) => {
                    assert!(
                        text.len() <= MAX_FRAME_BYTES,
                        "server frame exceeded wire budget"
                    );
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
    ) -> (Self, Value) {
        let mut client = Self::connect(server.address).await;
        let challenge = client.hello(&server.public_key, seed).await;
        let signature = sign_device_challenge(seed, &server.public_key, &challenge);
        let mut params = json!({"signature": hex::encode(signature)});
        if let Some(name) = display_name {
            params["display_name"] = json!(name);
        }
        let result = client.ok("authenticate", params).await;
        (client, result)
    }
}

#[tokio::test]
async fn registration_authentication_and_status() {
    let directory = tempfile::tempdir().unwrap();
    let server = TestServer::start(directory.path(), fast_limits()).await;
    let seed = [1_u8; 32];
    let (mut ada, first) = Client::login(&server, &seed, Some("Ada")).await;
    assert_eq!(first["new_account"], Value::Bool(true));
    assert_eq!(first["display_name"], json!("Ada"));
    let status = ada.ok("status", Value::Null).await;
    assert_eq!(status["account_id"], first["account_id"]);
    assert_eq!(
        status["server_public_key"],
        json!(hex::encode(server.public_key))
    );
    assert_eq!(status["handle"], Value::Null);
    assert_eq!(
        ada.err(
            "hello",
            json!({"minimum_version": 1, "maximum_version": 1, "device_public_key": "00"})
        )
        .await,
        "already-authenticated"
    );
    let (mut again, resumed) = Client::login(&server, &seed, Some("other")).await;
    assert_eq!(resumed["new_account"], Value::Bool(false));
    assert_eq!(resumed["display_name"], json!("Ada"));
    assert_eq!(
        again.ok("status", Value::Null).await["account_id"],
        first["account_id"]
    );
    server.stop().await;
}

#[tokio::test]
async fn bad_signatures_and_versions_are_refused() {
    let directory = tempfile::tempdir().unwrap();
    let server = TestServer::start(directory.path(), fast_limits()).await;
    let mut client = Client::connect(server.address).await;
    let challenge = client.hello(&server.public_key, &[1_u8; 32]).await;
    let wrong = sign_device_challenge(&[9_u8; 32], &server.public_key, &challenge);
    assert_eq!(
        client
            .err("authenticate", json!({"signature": hex::encode(wrong)}))
            .await,
        "invalid-signature"
    );
    let mut client = Client::connect(server.address).await;
    assert_eq!(
        client
            .err(
                "hello",
                json!({"minimum_version": 2, "maximum_version": 2, "device_public_key": hex::encode([1_u8; 32])})
            )
            .await,
        "unsupported-version"
    );
    server.stop().await;
}

#[tokio::test]
async fn handles_are_unique_and_survive_restart() {
    let directory = tempfile::tempdir().unwrap();
    let server = TestServer::start(directory.path(), fast_limits()).await;
    let (mut ada, _) = Client::login(&server, &[1_u8; 32], Some("Ada")).await;
    let (mut bob, _) = Client::login(&server, &[2_u8; 32], Some("Bob")).await;
    assert_eq!(
        ada.ok("claim-handle", json!({"handle": "ada"})).await["handle"],
        json!("ada")
    );
    assert_eq!(
        ada.err("claim-handle", json!({"handle": "ada2"})).await,
        "handle-already-set"
    );
    assert_eq!(
        bob.err("claim-handle", json!({"handle": "ada"})).await,
        "handle-taken"
    );
    assert_eq!(
        bob.err("claim-handle", json!({"handle": "A"})).await,
        "invalid-handle"
    );
    assert_eq!(
        ada.err("resolve-handle", json!({"handle": "bob"})).await,
        "not-found"
    );
    assert_eq!(
        bob.ok("claim-handle", json!({"handle": "bob"})).await["handle"],
        json!("bob")
    );
    let resolved = ada.ok("resolve-handle", json!({"handle": "bob"})).await;
    assert_eq!(resolved["handle"], json!("bob"));
    assert_eq!(resolved["display_name"], json!("Bob"));
    assert_eq!(
        ada.err("resolve-handle", json!({"handle": "nobody"})).await,
        "not-found"
    );
    server.stop().await;

    let server = TestServer::start(directory.path(), fast_limits()).await;
    let (mut ada, _) = Client::login(&server, &[1_u8; 32], None).await;
    assert_eq!(ada.ok("status", Value::Null).await["handle"], json!("ada"));
    assert!(matches!(
        Storage::open(
            &directory.path().join("server.db"),
            Zeroizing::new([9_u8; 32])
        ),
        Err(StorageError::WrongKey)
    ));
    server.stop().await;
}

#[tokio::test]
async fn chat_methods_are_not_part_of_the_protocol() {
    let directory = tempfile::tempdir().unwrap();
    let server = TestServer::start(directory.path(), fast_limits()).await;
    let (mut ada, _) = Client::login(&server, &[1_u8; 32], None).await;
    ada.send_raw(
        json!({"version": 1, "id": "x", "method": "create-workspace", "params": {"name": "team"}})
            .to_string(),
    )
    .await;
    let frame = ada
        .next_frame()
        .await
        .expect("unknown methods are rejected");
    assert_eq!(frame["ok"], Value::Bool(false));
    assert_eq!(frame["error"]["code"], json!("invalid-request"));
    server.stop().await;
}

#[tokio::test]
async fn hosted_chat_schema_is_refused() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("server.db");
    {
        let connection = rusqlite::Connection::open(&path).unwrap();
        connection
            .execute(
                "CREATE TABLE meta (key TEXT PRIMARY KEY, value BLOB NOT NULL)",
                [],
            )
            .unwrap();
        connection
            .execute(
                "INSERT INTO meta (key, value) VALUES ('schema_version', ?1)",
                rusqlite::params![b"1".as_slice()],
            )
            .unwrap();
    }
    let opened = Storage::open(&path, Zeroizing::new(STORAGE_KEY));
    let Err(error) = opened else {
        panic!("schema 1 database opened");
    };
    let StorageError::UnsupportedSchema(version) = error else {
        panic!("expected schema refusal, got {error}");
    };
    assert!(version.starts_with('1'), "{version}");
}

#[tokio::test]
async fn connection_limits_reject_excess_clients() {
    let directory = tempfile::tempdir().unwrap();
    let limits = HostLimits {
        max_connections: 2,
        max_connections_per_ip: 2,
        session: fast_limits().session,
        shutdown_grace: Duration::from_secs(1),
    };
    let server = TestServer::start(directory.path(), limits).await;
    let (_first, _) = Client::login(&server, &[1_u8; 32], None).await;
    let (_second, _) = Client::login(&server, &[2_u8; 32], None).await;
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

fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

#[allow(clippy::too_many_arguments)]
fn bind_params(
    server_public_key: &[u8; 32],
    account_id: &str,
    handle: &str,
    device_seed: &[u8; 32],
    nostr: &NostrSecret,
    nonce: [u8; 32],
    timestamp: u64,
    damage_device: bool,
    damage_nostr: bool,
) -> Value {
    let transcript = nostr_bind_transcript(
        server_public_key,
        account_id,
        handle,
        &nostr.public_key(),
        &nonce,
        timestamp,
    );
    let mut device_signature = SigningKey::from_bytes(device_seed)
        .sign(&transcript)
        .to_bytes();
    let mut nostr_signature = nostr.sign(&transcript).unwrap();
    if damage_device {
        device_signature[0] ^= 0xff;
    }
    if damage_nostr {
        nostr_signature[0] ^= 0xff;
    }
    json!({
        "nostr_public_key": hex::encode(nostr.public_key()),
        "nonce": hex::encode(nonce),
        "timestamp": timestamp,
        "device_signature": hex::encode(device_signature),
        "nostr_signature": hex::encode(nostr_signature),
    })
}

async fn http_get(address: SocketAddr, path: &str) -> (u16, String, String) {
    let mut stream = TcpStream::connect(address).await.unwrap();
    let request = format!("GET {path} HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n");
    stream.write_all(request.as_bytes()).await.unwrap();
    let mut buffer = Vec::new();
    stream.read_to_end(&mut buffer).await.unwrap();
    let text = String::from_utf8(buffer).unwrap();
    let status: u16 = text
        .lines()
        .next()
        .unwrap()
        .split_whitespace()
        .nth(1)
        .unwrap()
        .parse()
        .unwrap();
    let (head, body) = text.split_once("\r\n\r\n").unwrap();
    (status, head.to_owned(), body.to_owned())
}

#[tokio::test]
async fn nostr_bind_requires_both_proofs_and_nip05_serves_the_handle() {
    let directory = tempfile::tempdir().unwrap();
    let server = TestServer::start(directory.path(), fast_limits()).await;
    let nsec = "nsec1vl029mgpspedva04g90vltkh6fvh240zqtv9k0t9af8935ke9laqsnlfe5";
    let nostr = NostrSecret::from_nsec(nsec).unwrap();
    let (mut ada, registered) = Client::login(&server, &[1_u8; 32], Some("Ada")).await;
    let account_id = registered["account_id"].as_str().unwrap().to_owned();
    assert_eq!(
        ada.err(
            "bind-nostr",
            bind_params(
                &server.public_key,
                &account_id,
                "ada",
                &[1_u8; 32],
                &nostr,
                [1_u8; 32],
                unix_now(),
                false,
                false
            )
        )
        .await,
        "invalid-handle"
    );
    ada.ok("claim-handle", json!({"handle": "ada"})).await;
    let now = unix_now();
    let bound = ada
        .ok(
            "bind-nostr",
            bind_params(
                &server.public_key,
                &account_id,
                "ada",
                &[1_u8; 32],
                &nostr,
                [2_u8; 32],
                now,
                false,
                false,
            ),
        )
        .await;
    assert_eq!(
        bound["nostr_public_key"],
        json!(hex::encode(nostr.public_key()))
    );
    assert_eq!(bound["npub"], json!(nostr.npub()));
    assert_eq!(
        ada.err(
            "bind-nostr",
            bind_params(
                &server.public_key,
                &account_id,
                "ada",
                &[1_u8; 32],
                &nostr,
                [2_u8; 32],
                now,
                false,
                false
            ),
        )
        .await,
        "replayed-proof"
    );
    assert_eq!(
        ada.err(
            "bind-nostr",
            bind_params(
                &server.public_key,
                &account_id,
                "ada",
                &[1_u8; 32],
                &nostr,
                [3_u8; 32],
                now,
                false,
                true
            ),
        )
        .await,
        "invalid-signature"
    );
    assert_eq!(
        ada.err(
            "bind-nostr",
            bind_params(
                &server.public_key,
                &account_id,
                "ada",
                &[1_u8; 32],
                &nostr,
                [4_u8; 32],
                now,
                true,
                false
            ),
        )
        .await,
        "invalid-signature"
    );
    assert_eq!(
        ada.err(
            "bind-nostr",
            bind_params(
                &server.public_key,
                &account_id,
                "ada",
                &[1_u8; 32],
                &nostr,
                [5_u8; 32],
                now.saturating_sub(3600),
                false,
                false
            ),
        )
        .await,
        "invalid-request"
    );

    let (mut bob, bob_account) = Client::login(&server, &[2_u8; 32], Some("Bob")).await;
    let bob_id = bob_account["account_id"].as_str().unwrap().to_owned();
    bob.ok("claim-handle", json!({"handle": "bob"})).await;
    assert_eq!(
        bob.err(
            "bind-nostr",
            bind_params(
                &server.public_key,
                &bob_id,
                "bob",
                &[2_u8; 32],
                &nostr,
                [6_u8; 32],
                now,
                false,
                false
            ),
        )
        .await,
        "nostr-pubkey-taken"
    );

    let (status, head, body) = http_get(server.address, "/.well-known/nostr.json?name=ada").await;
    assert_eq!(status, 200);
    assert!(
        head.to_ascii_lowercase()
            .contains("access-control-allow-origin: *")
    );
    let document: Value = serde_json::from_str(&body).unwrap();
    assert_eq!(
        document["names"]["ada"],
        json!(hex::encode(nostr.public_key()))
    );
    assert!(document.get("relays").is_none());
    let (status, head, body) =
        http_get(server.address, "/.well-known/nostr.json?name=nobody").await;
    assert_eq!(status, 404);
    assert!(
        head.to_ascii_lowercase()
            .contains("access-control-allow-origin: *")
    );
    assert_eq!(
        serde_json::from_str::<Value>(&body).unwrap()["names"],
        json!({})
    );
    let (status, _, _) = http_get(server.address, "/.well-known/nostr.json?name=Not_A_Name").await;
    assert_eq!(
        status, 404,
        "NIP-05 names are case-insensitive, so this is an unknown handle"
    );
    let (status, _, _) = http_get(server.address, "/.well-known/nostr.json?name=bad%20name").await;
    assert_eq!(status, 400);
    let (status, _, _) = http_get(server.address, "/.well-known/nostr.json").await;
    assert_eq!(status, 400);

    let transcript = nostr_unbind_transcript(
        &server.public_key,
        &account_id,
        "ada",
        &nostr.public_key(),
        &[7_u8; 32],
        now,
    );
    let device_signature = SigningKey::from_bytes(&[1_u8; 32])
        .sign(&transcript)
        .to_bytes();
    ada.ok(
        "unbind-nostr",
        json!({
            "nonce": hex::encode([7_u8; 32]),
            "timestamp": now,
            "device_signature": hex::encode(device_signature),
        }),
    )
    .await;
    let (status, _, _) = http_get(server.address, "/.well-known/nostr.json?name=Ada").await;
    assert_eq!(status, 404);

    let replacement = NostrSecret::generate().unwrap();
    let rebound = ada
        .ok(
            "bind-nostr",
            bind_params(
                &server.public_key,
                &account_id,
                "ada",
                &[1_u8; 32],
                &replacement,
                [8_u8; 32],
                now,
                false,
                false,
            ),
        )
        .await;
    assert_eq!(
        rebound["nostr_public_key"],
        json!(hex::encode(replacement.public_key()))
    );
    let (status, _, body) = http_get(server.address, "/.well-known/nostr.json?name=ada").await;
    assert_eq!(status, 200);
    assert_eq!(
        serde_json::from_str::<Value>(&body).unwrap()["names"]["ada"],
        json!(hex::encode(replacement.public_key()))
    );
    server.stop().await;
}
