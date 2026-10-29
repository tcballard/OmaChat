//! The daemon's handle-server transport against a real in-process server:
//! pinned authentication, handle claims and panic erasure.

use omachat_proto::ipc::{Command, ErrorBody, Request, ResponseOutcome, VERSION};
use omachat_server::{
    HostLimits, HostReport, ServerIdentity, ServiceConfig, SessionLimits, Storage, run_host,
    spawn_service,
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
    sync::oneshot,
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
        }),
        dm_relays: Vec::new(),
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
    service: Option<omachatd::HostedService>,
    _state: tempfile::TempDir,
}

impl Daemon {
    async fn start(config: DaemonConfig) -> Self {
        let state = tempdir().unwrap();
        let hub = EventHub::default();
        let core = DaemonCore::open(state.path(), config, hub).await.unwrap();
        let service = core.start_hosted_with(fast_timeouts()).unwrap();
        Self {
            core,
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
        .request(Command::HostedClaimHandle {
            handle: "mallory".into(),
        })
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
async fn claim_and_resolve_use_the_server_handle_directory() {
    let directory = tempdir().unwrap();
    let server = TestServer::start(directory.path(), None).await;
    let alice = Daemon::start(hosted_config(server.address, server.public_key, "Alice")).await;
    let bob = Daemon::start(hosted_config(server.address, server.public_key, "Bob")).await;
    alice.wait_connected().await;
    bob.wait_connected().await;
    assert_eq!(
        alice
            .ok(Command::HostedClaimHandle {
                handle: "alice".into()
            })
            .await["handle"],
        "alice"
    );
    assert_eq!(alice.ok(Command::Status).await["hosted"]["handle"], "alice");
    let resolved = bob
        .ok(Command::HostedResolveHandle {
            handle: "alice".into(),
        })
        .await;
    assert_eq!(resolved["handle"], "alice");
    assert_eq!(resolved["display_name"], "Alice");
    let taken = alice
        .request(Command::HostedClaimHandle {
            handle: "bob".into(),
        })
        .await
        .unwrap_err();
    assert!(
        taken.message.contains("handle") || taken.code == omachat_proto::ipc::ErrorCode::Conflict
    );
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
    assert!(
        daemon
            .request(Command::HostedClaimHandle {
                handle: "alice".into()
            })
            .await
            .is_err()
    );
    daemon.shutdown().await;
    server.stop().await;
}
