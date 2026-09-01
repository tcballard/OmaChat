use std::time::Duration;

use omachat_crypto::{
    AccountSecrets, DevicePublicKeys, DisplayName, GlobalHandle, IdentitySecrets,
};
use omachat_proto::ipc::{Command, Request, ResponseOutcome, VERSION};
use omachat_registry::{CommandId, HandleClaim};
use omachat_registry_host::{RegistryHostLimits, run_registry_host};
use omachat_registry_transport::{RegistryClient, RegistryService, RegistryWebSocketTransport};
use omachat_store::{RequestedProvider, SealedStore};
use omachatd::{
    DaemonConfig, DaemonCore, EventHub, RegistryClientConfig, RequestHandler, StorageProviderConfig,
};
use serde_json::Value;
use tempfile::tempdir;
use tokio::{net::TcpListener, sync::oneshot, time::sleep};

fn account(seed: u8) -> AccountSecrets {
    AccountSecrets::from_seeds([seed; 32], [seed.wrapping_add(1); 32])
}

fn device_keys(seed: u8) -> DevicePublicKeys {
    let signing = account(seed.wrapping_add(10)).public_identity();
    let nostr = IdentitySecrets::from_seeds(
        [seed.wrapping_add(20); 32],
        [seed.wrapping_add(21); 32],
        [seed.wrapping_add(22); 32],
    )
    .device_nostr_identity()
    .expect("Nostr identity");
    DevicePublicKeys {
        signing_public_key: signing.account_root_public_key,
        noise_public_key: [seed.wrapping_add(30); 32],
        nostr_public_key: *nostr.public_key(),
    }
}

fn claim(account: &AccountSecrets, handle: &str) -> HandleClaim {
    let binding = account.sign_local_binding(
        Some(GlobalHandle::parse(handle).expect("handle")),
        Some(DisplayName::parse("Registry User").expect("display name")),
        device_keys(1),
        1,
        1_788_000_001,
    );
    HandleClaim::sign(CommandId::from_bytes([1; 32]), 0, binding, account).expect("claim")
}

async fn resolve(core: &DaemonCore, handle: &str) -> Value {
    match core
        .handle(Request {
            version: VERSION,
            id: "registry-resolution".into(),
            command: Command::ResolveRegistryHandle {
                handle: handle.into(),
            },
        })
        .await
    {
        ResponseOutcome::Ok { result } => result,
        ResponseOutcome::Error { error } => panic!("registry resolution failed: {error:?}"),
    }
}

#[tokio::test]
async fn verified_handle_resolution_is_explicitly_online_then_offline() {
    let registry_directory = tempdir().expect("registry directory");
    let daemon_directory = tempdir().expect("daemon directory");
    let registry_store = SealedStore::open(registry_directory.path(), RequestedProvider::File)
        .await
        .expect("registry store");
    let mut registry = RegistryService::open(&registry_store, [73; 32]).expect("registry");
    let pinned_key = registry.verifying_key();
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("registry listener");
    let endpoint = format!(
        "ws://{}/registry-v1",
        listener.local_addr().expect("address")
    );
    let (shutdown_tx, shutdown_rx) = oneshot::channel();
    let host = run_registry_host(
        listener,
        &mut registry,
        RegistryHostLimits::default(),
        || Ok(100),
        async {
            let _ = shutdown_rx.await;
        },
    );
    let client = async {
        let mut registry_client = RegistryClient::new(
            RegistryWebSocketTransport::new(&endpoint).expect("transport"),
            pinned_key,
        );
        registry_client
            .claim(&claim(&account(1), "alice"))
            .await
            .expect("accepted claim");
        let core = DaemonCore::open(
            daemon_directory.path(),
            DaemonConfig {
                storage_provider: StorageProviderConfig::File,
                registry: Some(RegistryClientConfig {
                    endpoint,
                    pinned_public_key: hex::encode(pinned_key),
                    max_age_seconds: 300,
                }),
                ..DaemonConfig::default()
            },
            EventHub::default(),
        )
        .await
        .expect("daemon core");

        let online = resolve(&core, "alice").await;
        assert_eq!(online["source"], "online");
        assert_eq!(online["evidence_status"], "fresh");
        assert_eq!(online["receipt_verified"], true);
        assert_eq!(online["usable_current_evidence"], true);
        assert_eq!(online["registry_sequence"], 1);

        shutdown_tx.send(()).expect("stop registry");
        sleep(Duration::from_millis(100)).await;
        let offline = resolve(&core, "alice").await;
        assert_eq!(offline["source"], "offline");
        assert_eq!(offline["evidence_status"], "fresh");
        assert_eq!(offline["receipt_verified"], true);
        assert_eq!(offline["usable_current_evidence"], true);
        let cached = match core
            .handle(Request {
                version: VERSION,
                id: "cached-registry-resolution".into(),
                command: Command::ShowRegistryHandle {
                    handle: "alice".into(),
                },
            })
            .await
        {
            ResponseOutcome::Ok { result } => result,
            ResponseOutcome::Error { error } => panic!("cached lookup failed: {error:?}"),
        };
        assert_eq!(cached["source"], "cache-only");
        assert_eq!(cached["evidence_status"], "fresh");
        assert_eq!(cached["receipt_verified"], true);
    };
    let (report, ()) = tokio::join!(host, client);
    let report = report.expect("host report");
    assert_eq!(report.completed_responses, 2);
}
