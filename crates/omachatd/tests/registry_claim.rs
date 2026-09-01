use std::time::{SystemTime, UNIX_EPOCH};

use omachat_crypto::GlobalHandle;
use omachat_proto::ipc::{Command, ErrorCode, Request, ResponseOutcome, VERSION};
use omachat_registry::{CommandId, RegistryState};
use omachat_registry_host::{RegistryHostLimits, run_registry_host};
use omachat_registry_transport::RegistryService;
use omachat_store::{
    AccountVault, IdentityVault, RegistryCacheLookup, RegistryClaimIntentStore, RequestedProvider,
    SealedStore, VerifiedRegistryCache,
};
use omachatd::{
    CoreError, DaemonConfig, DaemonCore, EventHub, RegistryClientConfig, RequestHandler,
    StorageProviderConfig,
};
use tempfile::tempdir;
use tokio::{net::TcpListener, sync::oneshot};

fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("clock")
        .as_secs()
}

fn config(endpoint: String, pinned_key: [u8; 32]) -> DaemonConfig {
    DaemonConfig {
        storage_provider: StorageProviderConfig::File,
        account_handle: Some("alice".into()),
        registry: Some(RegistryClientConfig {
            endpoint,
            pinned_public_key: hex::encode(pinned_key),
            max_age_seconds: 300,
        }),
        ..DaemonConfig::default()
    }
}

#[tokio::test]
async fn pending_claim_replays_after_restart_and_clears_after_durable_receipt() {
    let registry_directory = tempdir().expect("registry directory");
    let daemon_directory = tempdir().expect("daemon directory");
    let daemon_store = SealedStore::open(daemon_directory.path(), RequestedProvider::File)
        .await
        .expect("daemon store");
    let identity = IdentityVault::load_or_create(&daemon_store).expect("identity");
    let account = AccountVault::load_or_create(
        &daemon_store,
        &identity,
        Some(GlobalHandle::parse("alice").expect("handle")),
        None,
        now(),
    )
    .expect("account");
    let command_id = CommandId::from_bytes([81; 32]);
    let pending = account
        .sign_registry_handle_claim(command_id, 0)
        .expect("pending claim");
    RegistryClaimIntentStore::new(&daemon_store)
        .prepare(&pending)
        .expect("seal pending claim");
    drop(account);
    drop(identity);
    drop(daemon_store);

    let registry_store = SealedStore::open(registry_directory.path(), RequestedProvider::File)
        .await
        .expect("registry store");
    let mut registry = RegistryService::open(&registry_store, [82; 32]).expect("registry");
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
        || Ok(now()),
        async {
            let _ = shutdown_rx.await;
        },
    );
    let client = async {
        let core = DaemonCore::open(
            daemon_directory.path(),
            config(endpoint, pinned_key),
            EventHub::default(),
        )
        .await
        .expect("daemon core");
        let result = core
            .handle(Request {
                version: VERSION,
                id: "claim-handle".into(),
                command: Command::ClaimRegistryHandle {
                    handle: "alice".into(),
                    confirmation: "alice".into(),
                },
            })
            .await;
        let ResponseOutcome::Ok { result } = result else {
            panic!("claim command failed: {result:?}");
        };
        assert_eq!(result["claim_status"], "accepted");
        assert_eq!(result["receipt_verified"], true);
        assert_eq!(result["usable_current_evidence"], true);
        drop(core);
        shutdown_tx.send(()).expect("stop registry");
    };
    let (report, ()) = tokio::join!(host, client);
    assert_eq!(
        report.expect("host report").completed_responses,
        1,
        "pending replay skips a new preflight"
    );

    let reopened = SealedStore::open(daemon_directory.path(), RequestedProvider::File)
        .await
        .expect("reopen daemon store");
    assert_eq!(
        RegistryClaimIntentStore::new(&reopened)
            .load()
            .expect("load pending intent"),
        None
    );
    let cache = VerifiedRegistryCache::load_or_create(&reopened, pinned_key)
        .expect("verified registry cache");
    let RegistryCacheLookup::Fresh(cached) =
        cache.lookup_handle(&GlobalHandle::parse("alice").expect("handle"), now(), 300)
    else {
        panic!("verified claim receipt was not cached");
    };
    assert_eq!(cached.record.claim.command_id(), command_id);
}

#[tokio::test]
async fn offline_preflight_never_creates_a_new_claim_intent() {
    let daemon_directory = tempdir().expect("daemon directory");
    let unused = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("temporary listener");
    let endpoint = format!("ws://{}/registry-v1", unused.local_addr().expect("address"));
    drop(unused);
    let pinned_key = RegistryState::from_signing_seed([83; 32]).verifying_key();
    let core = DaemonCore::open(
        daemon_directory.path(),
        config(endpoint, pinned_key),
        EventHub::default(),
    )
    .await
    .expect("daemon core");
    let rejected = core
        .handle(Request {
            version: VERSION,
            id: "wrong-confirmation".into(),
            command: Command::ClaimRegistryHandle {
                handle: "alice".into(),
                confirmation: "bob".into(),
            },
        })
        .await;
    assert!(matches!(
        rejected,
        ResponseOutcome::Error {
            error: omachat_proto::ipc::ErrorBody {
                code: ErrorCode::Conflict,
                ..
            }
        }
    ));
    assert!(matches!(
        core.claim_configured_registry_handle(
            &GlobalHandle::parse("alice").expect("handle"),
            now(),
        )
        .await,
        Err(CoreError::RegistryClaimPreflightOffline)
    ));
    drop(core);

    let reopened = SealedStore::open(daemon_directory.path(), RequestedProvider::File)
        .await
        .expect("reopen store");
    assert_eq!(
        RegistryClaimIntentStore::new(&reopened)
            .load()
            .expect("load pending intent"),
        None
    );
}
