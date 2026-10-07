//! The daemon's hosted transport against a real in-process `omachat-server`:
//! pinned authentication, conversations, messages, receipts, history,
//! workspace administration, and sends that wait for a reconnect.

use omachat_proto::ipc::{Command, ErrorBody, Event, Request, ResponseOutcome, Topic, VERSION};
use omachat_server::{
    HostLimits, HostReport, Registration, ServerIdentity, ServiceConfig, SessionLimits, Storage,
    run_host, spawn_service,
};
use omachatd::{
    DaemonConfig, DaemonCore, EventHub, HostedConfig, HostedTimeouts, RequestHandler,
    StorageProviderConfig,
};
use serde_json::Value;
use std::{net::SocketAddr, path::Path, sync::Arc, time::Duration};
use tempfile::tempdir;
use tokio::{
    net::TcpListener,
    sync::{mpsc, oneshot},
    task::JoinHandle,
    time::{Instant, sleep, timeout},
};
use zeroize::Zeroizing;

const STORAGE_KEY: [u8; 32] = [42_u8; 32];
const SERVER_SEED: [u8; 32] = [7_u8; 32];
const WAIT: Duration = Duration::from_secs(10);

struct TestServer {
    address: SocketAddr,
    public_key: [u8; 32],
    stop: Option<oneshot::Sender<()>>,
    task: JoinHandle<HostReport>,
}

impl TestServer {
    async fn start(directory: &Path, address: Option<SocketAddr>) -> Self {
        let storage =
            Storage::open(&directory.join("messages.db"), Zeroizing::new(STORAGE_KEY)).unwrap();
        let identity = Arc::new(ServerIdentity::from_seed(&SERVER_SEED));
        let public_key = identity.public_key();
        let service = spawn_service(
            storage,
            ServiceConfig {
                registration: Registration::Open,
                server_public_key: public_key,
            },
        )
        .unwrap();
        let listener = match address {
            Some(address) => TcpListener::bind(address).await.unwrap(),
            None => TcpListener::bind("127.0.0.1:0").await.unwrap(),
        };
        let address = listener.local_addr().unwrap();
        let limits = HostLimits {
            session: SessionLimits {
                requests_per_second: 1000,
                request_burst: 1000,
                ..SessionLimits::default()
            },
            ..HostLimits::default()
        };
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

fn hosted_config(address: SocketAddr, pin: [u8; 32], display_name: &str) -> DaemonConfig {
    DaemonConfig {
        storage_provider: StorageProviderConfig::File,
        hosted: Some(HostedConfig {
            url: format!("ws://{address}"),
            pinned_server_public_key: hex::encode(pin),
            display_name: Some(display_name.to_owned()),
            invite_code: None,
        }),
    }
}

fn fast_timeouts() -> HostedTimeouts {
    HostedTimeouts {
        connect: Duration::from_secs(5),
        request: Duration::from_secs(5),
        send: Duration::from_secs(3),
        initial_backoff: Duration::from_millis(200),
        max_backoff: Duration::from_millis(500),
        keepalive: Duration::from_secs(30),
    }
}

struct Daemon {
    core: DaemonCore,
    events: mpsc::Receiver<Event>,
    service: Option<omachatd::HostedService>,
    _state: tempfile::TempDir,
}

impl Daemon {
    async fn start(config: DaemonConfig) -> Self {
        let state = tempdir().unwrap();
        let hub = EventHub::default();
        let events = hub.subscribe();
        let core = DaemonCore::open(state.path(), config, hub).await.unwrap();
        let service = core.start_hosted_with(fast_timeouts()).unwrap();
        Self {
            core,
            events,
            service,
            _state: state,
        }
    }

    async fn request(&self, command: Command) -> Result<Value, ErrorBody> {
        match self
            .core
            .handle(Request {
                version: VERSION,
                id: "hosted-test".into(),
                command,
            })
            .await
        {
            ResponseOutcome::Ok { result } => Ok(result),
            ResponseOutcome::Error { error } => Err(error),
        }
    }

    async fn ok(&self, command: Command) -> Value {
        self.request(command)
            .await
            .unwrap_or_else(|error| panic!("daemon error: {}", error.message))
    }

    async fn wait_for_status(&self, description: &str, accept: impl Fn(&Value) -> bool) -> Value {
        let deadline = Instant::now() + WAIT;
        loop {
            let status = self.ok(Command::Status).await;
            if accept(&status["hosted"]) {
                return status;
            }
            assert!(
                Instant::now() < deadline,
                "timed out waiting for {description}; hosted status is {}",
                status["hosted"]
            );
            sleep(Duration::from_millis(50)).await;
        }
    }

    async fn wait_connected(&self) -> Value {
        self.wait_for_status("connection", |hosted| hosted["state"] == "connected")
            .await
    }

    /// Drain events until one matches. Events that arrive earlier are
    /// discarded, which is what a client that polls a topic would do too.
    async fn next_event(&mut self, description: &str, accept: impl Fn(&Event) -> bool) -> Event {
        let deadline = Instant::now() + WAIT;
        loop {
            let remaining = deadline.saturating_duration_since(Instant::now());
            let event = timeout(remaining, self.events.recv())
                .await
                .unwrap_or_else(|_| panic!("timed out waiting for {description}"))
                .expect("event hub closed");
            if accept(&event) {
                return event;
            }
        }
    }

    async fn shutdown(self) {
        if let Some(service) = self.service {
            service.shutdown().await;
        }
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn daemon_pins_the_server_key_and_refuses_an_impostor() {
    let plain = Daemon::start(DaemonConfig {
        storage_provider: StorageProviderConfig::File,
        ..DaemonConfig::default()
    })
    .await;
    assert!(plain.service.is_none());
    assert_eq!(
        plain.ok(Command::Status).await["hosted"]["state"],
        "disabled"
    );

    let directory = tempdir().unwrap();
    let server = TestServer::start(directory.path(), None).await;
    let alice = Daemon::start(hosted_config(server.address, server.public_key, "Alice")).await;
    let status = alice.wait_connected().await;
    assert_eq!(status["hosted"]["display_name"], "Alice");
    assert!(status["hosted"]["account_id"].is_string());
    assert_eq!(status["hosted"]["url"], format!("ws://{}", server.address));
    assert_eq!(
        status["hosted"]["server_public_key"],
        hex::encode(server.public_key)
    );

    let impostor_pin = ServerIdentity::from_seed(&[9_u8; 32]).public_key();
    let mallory = Daemon::start(hosted_config(server.address, impostor_pin, "Mallory")).await;
    let status = mallory
        .wait_for_status("pin refusal", |hosted| hosted["state"] == "disconnected")
        .await;
    assert!(
        status["hosted"]["reason"]
            .as_str()
            .unwrap()
            .contains("pinned key"),
        "reason was {}",
        status["hosted"]["reason"]
    );
    assert!(status["hosted"]["account_id"].is_null());
    let error = mallory
        .request(Command::HostedConversations)
        .await
        .unwrap_err();
    assert_eq!(error.code, omachat_proto::ipc::ErrorCode::Unavailable);

    mallory.shutdown().await;
    alice.shutdown().await;
    let report = server.stop().await;
    assert_eq!(
        report.authenticated_sessions, 1,
        "only the correctly pinned daemon may authenticate"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn two_daemons_exchange_messages_receipts_history_and_channels() {
    let directory = tempdir().unwrap();
    let server = TestServer::start(directory.path(), None).await;
    let mut alice = Daemon::start(hosted_config(server.address, server.public_key, "Alice")).await;
    let mut bob = Daemon::start(hosted_config(server.address, server.public_key, "Bob")).await;
    let alice_account = alice.wait_connected().await["hosted"]["account_id"]
        .as_str()
        .unwrap()
        .to_owned();
    let bob_account = bob.wait_connected().await["hosted"]["account_id"]
        .as_str()
        .unwrap()
        .to_owned();
    assert_ne!(alice_account, bob_account);

    alice
        .ok(Command::HostedClaimHandle {
            handle: "alice".into(),
        })
        .await;
    bob.ok(Command::HostedClaimHandle {
        handle: "bob".into(),
    })
    .await;
    assert_eq!(alice.ok(Command::Status).await["hosted"]["handle"], "alice");
    let taken = alice
        .request(Command::HostedClaimHandle {
            handle: "bob".into(),
        })
        .await
        .unwrap_err();
    assert_eq!(taken.code, omachat_proto::ipc::ErrorCode::Conflict);
    let resolved = alice
        .ok(Command::HostedResolveHandle {
            handle: "bob".into(),
        })
        .await;
    assert_eq!(resolved["account_id"], bob_account);

    // Direct conversation: Alice opens it, Bob learns about it by event.
    let dm = alice
        .ok(Command::HostedOpenDm {
            handle: "bob".into(),
        })
        .await;
    let conversation = dm["conversation"].as_str().unwrap().to_owned();
    assert!(conversation.starts_with("hosted:"));
    assert_eq!(dm["kind"], "dm");
    assert_eq!(dm["name"], "@bob");
    let announced = bob
        .next_event("Bob's conversation event", |event| {
            event.topic == Topic::Conversations && event.payload["conversation"] == conversation
        })
        .await;
    assert_eq!(announced.payload["name"], "@alice");

    // A send returns the server sequence, reaches Bob live, and Bob's
    // automatic delivered receipt comes back to Alice.
    let sent = alice
        .ok(Command::Send {
            conversation: conversation.clone(),
            text: "hi bob".into(),
        })
        .await;
    assert_eq!(sent["delivery"], "stored");
    assert_eq!(sent["sequence"], 1);
    assert_eq!(sent["duplicate"], false);
    let message_id = sent["id"].as_str().unwrap().to_owned();

    let received = bob
        .next_event("Bob's message", |event| {
            event.topic == Topic::Messages && event.payload["id"] == message_id
        })
        .await;
    assert_eq!(received.payload["text"], "hi bob");
    assert_eq!(received.payload["outgoing"], false);
    assert_eq!(received.payload["delivery"], "received");
    assert_eq!(received.payload["sender"], "@alice");
    assert_eq!(received.payload["conversation"], conversation);

    let own = alice
        .next_event("Alice's own message", |event| {
            event.topic == Topic::Messages && event.payload["id"] == message_id
        })
        .await;
    assert_eq!(own.payload["outgoing"], true);
    assert_eq!(own.payload["sender"], "You");
    assert_eq!(own.payload["delivery"], "stored");

    let delivered = alice
        .next_event("Bob's delivered receipt", |event| {
            event.topic == Topic::Delivery
                && event.payload["account_id"] == bob_account
                && event.payload["delivered_sequence"] == 1
        })
        .await;
    assert_eq!(delivered.payload["conversation"], conversation);
    assert_eq!(delivered.payload["read_sequence"], 0);

    // Read receipt and history.
    let read = bob
        .ok(Command::HostedMarkRead {
            conversation: conversation.clone(),
            sequence: 1,
        })
        .await;
    assert_eq!(read["read_sequence"], 1);
    alice
        .next_event("Bob's read receipt", |event| {
            event.topic == Topic::Delivery
                && event.payload["account_id"] == bob_account
                && event.payload["read_sequence"] == 1
        })
        .await;
    let history = bob
        .ok(Command::HostedHistory {
            conversation: conversation.clone(),
            before_sequence: None,
            limit: None,
        })
        .await;
    assert_eq!(history["messages"].as_array().unwrap().len(), 1);
    assert_eq!(history["messages"][0]["text"], "hi bob");
    assert_eq!(history["messages"][0]["outgoing"], false);
    assert_eq!(history["messages"][0]["sequence"], 1);
    let conversations = bob.ok(Command::HostedConversations).await;
    let listed = conversations["conversations"]
        .as_array()
        .unwrap()
        .iter()
        .find(|entry| entry["conversation"] == conversation)
        .expect("Bob lists the direct conversation");
    assert_eq!(listed["name"], "@alice");
    assert_eq!(listed["last_sequence"], 1);
    assert_eq!(listed["read_sequence"], 1);

    // An acknowledged send is never deduplicated against a later identical one.
    let again = alice
        .ok(Command::Send {
            conversation: conversation.clone(),
            text: "hi bob".into(),
        })
        .await;
    assert_eq!(again["sequence"], 2);
    assert_eq!(again["duplicate"], false);

    // Workspace administration, owner only.
    let workspace = alice
        .ok(Command::HostedCreateWorkspace {
            name: "Acme".into(),
        })
        .await;
    let workspace_id = workspace["workspace_id"].as_str().unwrap().to_owned();
    let channel = alice
        .ok(Command::HostedCreateChannel {
            workspace_id: workspace_id.clone(),
            name: "general".into(),
        })
        .await;
    let channel_conversation = channel["conversation"].as_str().unwrap().to_owned();
    // A non-member cannot even see the workspace; a member who is not the
    // owner is refused with a conflict. Both are the server's rules.
    let unseen = bob
        .request(Command::HostedCreateChannel {
            workspace_id: workspace_id.clone(),
            name: "random".into(),
        })
        .await
        .unwrap_err();
    assert_eq!(unseen.code, omachat_proto::ipc::ErrorCode::NotFound);
    let workspace_id_for_bob = workspace_id.clone();
    let added = alice
        .ok(Command::HostedAddMember {
            workspace_id,
            handle: "bob".into(),
        })
        .await;
    assert_eq!(added["channels_joined"], 1);
    let forbidden = bob
        .request(Command::HostedCreateChannel {
            workspace_id: workspace_id_for_bob.clone(),
            name: "random".into(),
        })
        .await
        .unwrap_err();
    assert_eq!(forbidden.code, omachat_proto::ipc::ErrorCode::Conflict);
    let joined = bob
        .next_event("Bob's channel event", |event| {
            event.topic == Topic::Conversations
                && event.payload["conversation"] == channel_conversation
        })
        .await;
    assert_eq!(joined.payload["name"], "general");
    assert_eq!(joined.payload["kind"], "channel");
    let channel_message = alice
        .ok(Command::Send {
            conversation: channel_conversation.clone(),
            text: "welcome".into(),
        })
        .await;
    let in_channel = bob
        .next_event("Bob's channel message", |event| {
            event.topic == Topic::Messages && event.payload["id"] == channel_message["id"]
        })
        .await;
    assert_eq!(in_channel.payload["conversation"], channel_conversation);

    let invalid = alice
        .request(Command::Send {
            conversation: "hosted:not/valid".into(),
            text: "x".into(),
        })
        .await
        .unwrap_err();
    assert_eq!(invalid.code, omachat_proto::ipc::ErrorCode::InvalidRequest);
    let missing = alice
        .request(Command::Send {
            conversation: "hosted:0000".into(),
            text: "x".into(),
        })
        .await
        .unwrap_err();
    assert_eq!(missing.code, omachat_proto::ipc::ErrorCode::NotFound);

    alice.shutdown().await;
    bob.shutdown().await;
    server.stop().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn sends_wait_for_a_reconnect_and_give_up_honestly() {
    let directory = tempdir().unwrap();
    let server = TestServer::start(directory.path(), None).await;
    let address = server.address;
    let public_key = server.public_key;
    let alice = Daemon::start(hosted_config(address, public_key, "Alice")).await;
    let mut bob = Daemon::start(hosted_config(address, public_key, "Bob")).await;
    alice.wait_connected().await;
    bob.wait_connected().await;
    bob.ok(Command::HostedClaimHandle {
        handle: "bob".into(),
    })
    .await;
    let conversation = alice
        .ok(Command::HostedOpenDm {
            handle: "bob".into(),
        })
        .await["conversation"]
        .as_str()
        .unwrap()
        .to_owned();

    // The server goes away; a send issued meanwhile completes once the
    // server is back, because the daemon retries until its send deadline.
    server.stop().await;
    alice
        .wait_for_status("disconnection", |hosted| hosted["state"] == "disconnected")
        .await;
    let sender = alice.core.clone();
    let pending_conversation = conversation.clone();
    let pending = tokio::spawn(async move {
        sender
            .handle(Request {
                version: VERSION,
                id: "pending".into(),
                command: Command::Send {
                    conversation: pending_conversation,
                    text: "after restart".into(),
                },
            })
            .await
    });
    sleep(Duration::from_millis(500)).await;
    let server = TestServer::start(directory.path(), Some(address)).await;
    let outcome = timeout(WAIT, pending).await.unwrap().unwrap();
    let ResponseOutcome::Ok { result } = outcome else {
        panic!("send after restart failed: {outcome:?}");
    };
    assert_eq!(result["delivery"], "stored");
    assert_eq!(result["sequence"], 1);
    alice.wait_connected().await;
    bob.wait_connected().await;
    let history = bob
        .ok(Command::HostedHistory {
            conversation: conversation.clone(),
            before_sequence: None,
            limit: None,
        })
        .await;
    assert_eq!(history["messages"].as_array().unwrap().len(), 1);
    assert_eq!(history["messages"][0]["text"], "after restart");
    bob.next_event("Bob's reconnect announcement", |event| {
        event.topic == Topic::Conversations && event.payload["conversation"] == conversation
    })
    .await;

    // With the server down past the send deadline, the daemon says so
    // instead of pretending, and the message is not stored anywhere.
    server.stop().await;
    alice
        .wait_for_status("second disconnection", |hosted| {
            hosted["state"] == "disconnected"
        })
        .await;
    let started = Instant::now();
    let error = alice
        .request(Command::Send {
            conversation: conversation.clone(),
            text: "lost".into(),
        })
        .await
        .unwrap_err();
    assert_eq!(error.code, omachat_proto::ipc::ErrorCode::Unavailable);
    assert!(
        error.message.contains("repeated safely"),
        "{}",
        error.message
    );
    assert!(
        started.elapsed() >= Duration::from_secs(3) && started.elapsed() < WAIT,
        "send must give up at the deadline, took {:?}",
        started.elapsed()
    );

    // Repeating the same text after the server returns stores it once.
    let server = TestServer::start(directory.path(), Some(address)).await;
    alice.wait_connected().await;
    let repeated = alice
        .ok(Command::Send {
            conversation: conversation.clone(),
            text: "lost".into(),
        })
        .await;
    assert_eq!(repeated["sequence"], 2);
    bob.wait_connected().await;
    let history = bob
        .ok(Command::HostedHistory {
            conversation,
            before_sequence: None,
            limit: None,
        })
        .await;
    let texts = history["messages"]
        .as_array()
        .unwrap()
        .iter()
        .map(|message| message["text"].as_str().unwrap().to_owned())
        .collect::<Vec<_>>();
    assert_eq!(texts, ["after restart", "lost"]);

    alice.shutdown().await;
    bob.shutdown().await;
    server.stop().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn panic_quiesces_hosted_transport_before_erasing_credentials() {
    let directory = tempdir().unwrap();
    let server = TestServer::start(directory.path(), None).await;
    let daemon = Daemon::start(hosted_config(server.address, server.public_key, "Alice")).await;
    daemon.wait_connected().await;
    let handle = daemon.service.as_ref().unwrap().handle();
    let issued = daemon.ok(Command::RequestPanicConfirmation).await;
    let token = std::fs::read_to_string(issued["token_path"].as_str().unwrap()).unwrap();
    let erased = timeout(
        WAIT,
        daemon.ok(Command::Panic {
            confirmation: token,
        }),
    )
    .await
    .unwrap();
    assert_eq!(erased["erased"], true);
    assert_eq!(handle.state(), omachatd::HostedState::Stopped);
    assert!(!daemon._state.path().exists());
    assert!(daemon.core.start_hosted().is_err());
    assert!(daemon.request(Command::HostedConversations).await.is_err());
    daemon.shutdown().await;
    server.stop().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn daemon_preserves_cursors_and_every_large_history_message() {
    let directory = tempdir().unwrap();
    let server = TestServer::start(directory.path(), None).await;
    let alice = Daemon::start(hosted_config(server.address, server.public_key, "Alice")).await;
    alice.wait_connected().await;
    let workspace = alice
        .ok(Command::HostedCreateWorkspace {
            name: "Paging".into(),
        })
        .await["workspace_id"]
        .as_str()
        .unwrap()
        .to_owned();
    let mut expected = std::collections::BTreeSet::new();
    for index in 0..40 {
        let result = alice
            .ok(Command::HostedCreateChannel {
                workspace_id: workspace.clone(),
                name: format!("channel{index}"),
            })
            .await;
        expected.insert(format!(
            "hosted:{}",
            result["conversation_id"].as_str().unwrap()
        ));
    }
    let mut result = alice.ok(Command::HostedConversations).await;
    let mut got = std::collections::BTreeSet::new();
    let mut cursors = std::collections::HashSet::new();
    loop {
        assert!(result.to_string().len() < omachat_proto::ipc::MAX_LINE_BYTES);
        for row in result["conversations"].as_array().unwrap() {
            assert!(got.insert(row["conversation"].as_str().unwrap().to_owned()));
        }
        let Some(cursor) = result["next_cursor"].as_str().map(str::to_owned) else {
            break;
        };
        assert!(cursors.insert(cursor.clone()));
        result = alice.ok(Command::HostedConversationsPage { cursor }).await;
    }
    assert!(!cursors.is_empty());
    assert_eq!(got, expected);
    let conversation = got.first().unwrap().clone();
    for index in 0..5 {
        alice
            .ok(Command::Send {
                conversation: conversation.clone(),
                text: format!("{index}{}", "x".repeat(4095)),
            })
            .await;
    }
    let mut before = None;
    let mut sequences = std::collections::BTreeSet::new();
    loop {
        let page = alice
            .ok(Command::HostedHistory {
                conversation: conversation.clone(),
                before_sequence: before,
                limit: Some(50),
            })
            .await;
        for message in page["messages"].as_array().unwrap() {
            assert_eq!(message["text"].as_str().unwrap().len(), 4096);
            assert!(sequences.insert(message["sequence"].as_u64().unwrap()));
        }
        before = page["next_before_sequence"].as_u64();
        if before.is_none() {
            break;
        }
    }
    assert_eq!(sequences, std::collections::BTreeSet::from([1, 2, 3, 4, 5]));
    assert!(
        alice
            .request(Command::HostedConversationsPage {
                cursor: "x".repeat(20000)
            })
            .await
            .is_err()
    );
    assert!(
        alice
            .request(Command::Send {
                conversation: conversation.clone(),
                text: "\u{0000}".repeat(2200)
            })
            .await
            .is_err()
    );
    assert_eq!(
        alice.ok(Command::Status).await["hosted"]["state"],
        "connected"
    );
    alice.shutdown().await;
    server.stop().await;
}
