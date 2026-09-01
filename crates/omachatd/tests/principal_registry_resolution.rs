use k256::schnorr::SigningKey as SchnorrSigningKey;
use omachat_crypto::{AccountSecrets, DevicePublicKeys, DisplayName, GlobalHandle};
use omachat_proto::ipc::{Command, Request, ResponseOutcome, VERSION};
use omachat_registry::{
    CommandId, HandleClaim,
    principal_proof::{
        NostrPrincipalControlPayload, NostrPrincipalControlProof, NostrPrincipalType,
    },
    proof_bearing_claim::{ProofBearingDeviceHandleClaim, device_authorisation_hash},
};
use omachat_registry_host::{RegistryHostLimits, run_principal_registry_host};
use omachat_registry_transport::{
    PrincipalRegistryClient, PrincipalRegistryService, RegistryWebSocketTransport,
};
use omachat_store::{RequestedProvider, SealedStore};
use omachatd::{
    DaemonConfig, DaemonCore, EventHub, RegistryClientConfig, RegistryProtocol, RequestHandler,
    StorageProviderConfig,
};
use tempfile::tempdir;
use tokio::{net::TcpListener, sync::oneshot};

fn nostr_public_key(secret: &[u8; 32]) -> [u8; 32] {
    SchnorrSigningKey::from_bytes(secret)
        .expect("Nostr key")
        .verifying_key()
        .to_bytes()
        .into()
}

fn claim() -> ProofBearingDeviceHandleClaim {
    let account = AccountSecrets::from_seeds([0x11; 32], [0x12; 32]);
    let nostr_secret = [0x31; 32];
    let public_key = nostr_public_key(&nostr_secret);
    let binding = account.sign_local_binding(
        Some(GlobalHandle::parse("alice").expect("handle")),
        Some(DisplayName::parse("Principal IPC Test").expect("display name")),
        DevicePublicKeys {
            signing_public_key: AccountSecrets::from_seeds([0x21; 32], [0x22; 32])
                .public_identity()
                .account_root_public_key,
            noise_public_key: [0x23; 32],
            nostr_public_key: public_key,
        },
        1,
        1_788_000_001,
    );
    let command_id = [0x41; 32];
    let root_claim = HandleClaim::sign(CommandId::from_bytes(command_id), 0, binding, &account)
        .expect("root claim");
    let payload = NostrPrincipalControlPayload::new(
        root_claim.claim_hash(),
        command_id,
        0,
        root_claim.binding().account_id.as_str(),
        "alice",
        NostrPrincipalType::Device,
        public_key,
        device_authorisation_hash(root_claim.binding()),
        1_788_000_002,
    )
    .expect("principal payload");
    let proof = NostrPrincipalControlProof::sign(payload, nostr_secret).expect("principal proof");
    ProofBearingDeviceHandleClaim::new(root_claim, proof).expect("proof-bearing claim")
}

async fn request(core: &DaemonCore, command: Command) -> serde_json::Value {
    match core
        .handle(Request {
            version: VERSION,
            id: "principal-registry-resolution".into(),
            command,
        })
        .await
    {
        ResponseOutcome::Ok { result } => result,
        ResponseOutcome::Error { error } => panic!("daemon error: {error:?}"),
    }
}

#[tokio::test]
async fn daemon_resolves_and_caches_verified_principal_handle_evidence() {
    let registry_directory = tempdir().expect("registry directory");
    let daemon_directory = tempdir().expect("daemon directory");
    let registry_store = SealedStore::open(registry_directory.path(), RequestedProvider::File)
        .await
        .expect("registry store");
    let mut registry =
        PrincipalRegistryService::open(&registry_store, [0x71; 32], None).expect("registry");
    let pinned_key = registry.verifying_key();
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("registry listener");
    let endpoint = format!(
        "ws://{}/principal-registry-v1",
        listener.local_addr().expect("registry address")
    );
    let (shutdown_tx, shutdown_rx) = oneshot::channel();
    let host = run_principal_registry_host(
        listener,
        &mut registry,
        RegistryHostLimits::default(),
        || Ok(1_788_000_003),
        async {
            let _ = shutdown_rx.await;
        },
    );
    let client = async {
        let claim = claim();
        let expected_public_key = claim.principal_proof().payload().nostr_public_key();
        PrincipalRegistryClient::new(
            RegistryWebSocketTransport::new(&endpoint).expect("claim transport"),
            pinned_key,
        )
        .claim_device(&claim)
        .await
        .expect("seed registry");

        let core = DaemonCore::open(
            daemon_directory.path(),
            DaemonConfig {
                storage_provider: StorageProviderConfig::File,
                registry: Some(RegistryClientConfig {
                    endpoint,
                    pinned_public_key: hex::encode(pinned_key),
                    max_age_seconds: 300,
                    protocol: RegistryProtocol::PrincipalProofV1,
                }),
                ..DaemonConfig::default()
            },
            EventHub::default(),
        )
        .await
        .expect("daemon core");

        let online = request(
            &core,
            Command::ResolveRegistryHandle {
                handle: "alice".into(),
            },
        )
        .await;
        assert_eq!(online["source"], "online");
        assert_eq!(online["evidence_status"], "fresh");
        assert_eq!(online["evidence_protocol"], "principal-proof-v1");
        assert_eq!(online["nostr_public_key"], hex::encode(expected_public_key));
        assert_eq!(
            online["nostr_public_key_provenance"],
            "principal-proof-verified"
        );
        assert_eq!(online["nostr_key_control_verified"], true);
        assert_eq!(online["account_root_authorisation_verified"], true);
        assert_eq!(online["receipt_chains_verified"], true);

        let cached = request(
            &core,
            Command::ShowRegistryHandle {
                handle: "alice".into(),
            },
        )
        .await;
        assert_eq!(cached["source"], "cache-only");
        assert_eq!(cached["principal_receipt_verified"], true);
        assert_eq!(
            cached["principal_receipt_hash"],
            online["principal_receipt_hash"]
        );
        shutdown_tx.send(()).expect("stop registry");
    };

    let (report, ()) = tokio::join!(host, client);
    let report = report.expect("host report");
    assert_eq!(report.completed_responses, 2);
    assert!(!report.forced_shutdown);
}
