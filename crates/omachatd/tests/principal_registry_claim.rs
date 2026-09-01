use std::time::{SystemTime, UNIX_EPOCH};

use omachat_crypto::GlobalHandle;
use omachat_proto::ipc::{Command, Request, ResponseOutcome, VERSION};
use omachat_registry_host::{RegistryHostLimits, run_principal_registry_host};
use omachat_registry_transport::PrincipalRegistryService;
use omachat_store::{
    PRINCIPAL_REGISTRY_CLAIM_INTENT_RECORD_NAME, PrincipalRegistryCacheLookup,
    PrincipalRegistryClaimIntentStore, RequestedProvider, SealedStore,
    VerifiedPrincipalRegistryCache,
};
use omachatd::{
    DaemonConfig, DaemonCore, EventHub, RegistryClientConfig, RegistryProtocol, RequestHandler,
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

async fn claim(core: &DaemonCore) -> serde_json::Value {
    match core
        .handle(Request {
            version: VERSION,
            id: "principal-registry-claim".into(),
            command: Command::ClaimRegistryHandle {
                handle: "alice".into(),
                confirmation: "alice".into(),
            },
        })
        .await
    {
        ResponseOutcome::Ok { result } => result,
        ResponseOutcome::Error { error } => panic!("principal claim failed: {error:?}"),
    }
}

#[tokio::test]
async fn daemon_builds_persists_and_exactly_replays_principal_claim() {
    let registry_directory = tempdir().expect("registry directory");
    let daemon_directory = tempdir().expect("daemon directory");
    let registry_store = SealedStore::open(registry_directory.path(), RequestedProvider::File)
        .await
        .expect("registry store");
    let mut registry =
        PrincipalRegistryService::open(&registry_store, [0x72; 32], None).expect("registry");
    let pinned_key = registry.verifying_key();
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("registry listener");
    let endpoint = format!(
        "ws://{}/principal-registry-v1",
        listener.local_addr().expect("registry address")
    );
    let config = DaemonConfig {
        storage_provider: StorageProviderConfig::File,
        account_handle: Some("alice".into()),
        registry: Some(RegistryClientConfig {
            endpoint,
            pinned_public_key: hex::encode(pinned_key),
            max_age_seconds: 300,
            protocol: RegistryProtocol::PrincipalProofV1,
        }),
        ..DaemonConfig::default()
    };
    let (shutdown_tx, shutdown_rx) = oneshot::channel();
    let host = run_principal_registry_host(
        listener,
        &mut registry,
        RegistryHostLimits::default(),
        || Ok(now()),
        async {
            let _ = shutdown_rx.await;
        },
    );
    let client = async {
        let core = DaemonCore::open(daemon_directory.path(), config.clone(), EventHub::default())
            .await
            .expect("daemon core");
        let first = claim(&core).await;
        assert_eq!(first["claim_status"], "accepted");
        assert_eq!(first["evidence_protocol"], "principal-proof-v1");
        assert_eq!(first["nostr_key_control_verified"], true);
        let first_principal_receipt = first["principal_receipt_hash"].clone();
        drop(core);

        let store = SealedStore::open(daemon_directory.path(), RequestedProvider::File)
            .await
            .expect("reopen daemon store");
        let handle = GlobalHandle::parse("alice").expect("handle");
        let cache = VerifiedPrincipalRegistryCache::load_or_create(&store, pinned_key)
            .expect("principal cache");
        let PrincipalRegistryCacheLookup::Fresh(cached) = cache.lookup_handle(&handle, now(), 300)
        else {
            panic!("fresh principal evidence missing");
        };
        PrincipalRegistryClaimIntentStore::new(&store)
            .prepare(&cached.evidence.claim)
            .expect("simulate crash before intent clear");
        drop(store);

        let reopened = DaemonCore::open(daemon_directory.path(), config, EventHub::default())
            .await
            .expect("reopened daemon");
        let replay = claim(&reopened).await;
        assert_eq!(replay["claim_status"], "accepted");
        assert_eq!(replay["principal_receipt_hash"], first_principal_receipt);
        drop(reopened);

        let store = SealedStore::open(daemon_directory.path(), RequestedProvider::File)
            .await
            .expect("final daemon store");
        assert_eq!(
            PrincipalRegistryClaimIntentStore::new(&store)
                .load()
                .expect("load final intent"),
            None
        );
        assert!(
            store
                .read(PRINCIPAL_REGISTRY_CLAIM_INTENT_RECORD_NAME)
                .is_err(),
            "completed intent record remained present"
        );
        shutdown_tx.send(()).expect("stop registry");
    };

    let (report, ()) = tokio::join!(host, client);
    let report = report.expect("host report");
    assert_eq!(report.completed_responses, 3);
    assert!(!report.forced_shutdown);
}
