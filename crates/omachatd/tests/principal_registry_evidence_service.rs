use k256::schnorr::SigningKey as SchnorrSigningKey;
use omachat_crypto::{AccountSecrets, DevicePublicKeys, DisplayName, GlobalHandle};
use omachat_registry::{
    CommandId, HandleClaim,
    principal_proof::{
        NostrPrincipalControlPayload, NostrPrincipalControlProof, NostrPrincipalType,
    },
    proof_bearing_claim::{ProofBearingDeviceHandleClaim, device_authorisation_hash},
};
use omachat_registry_host::{RegistryHostLimits, run_principal_registry_host};
use omachat_registry_transport::{PrincipalRegistryService, RegistryWebSocketTransport};
use omachat_store::{PrincipalRegistryCacheLookup, RequestedProvider, SealedStore};
use omachatd::PrincipalRegistryEvidenceService;
use tempfile::tempdir;
use tokio::{net::TcpListener, sync::oneshot};

fn nostr_public_key(secret: &[u8; 32]) -> [u8; 32] {
    SchnorrSigningKey::from_bytes(secret)
        .unwrap()
        .verifying_key()
        .to_bytes()
        .into()
}

fn claim() -> ProofBearingDeviceHandleClaim {
    let account = AccountSecrets::from_seeds([0x11; 32], [0x12; 32]);
    let nostr_secret = [0x31; 32];
    let public_key = nostr_public_key(&nostr_secret);
    let binding = account.sign_local_binding(
        Some(GlobalHandle::parse("alice").unwrap()),
        Some(DisplayName::parse("Daemon Principal Evidence Test").unwrap()),
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
    let root_claim =
        HandleClaim::sign(CommandId::from_bytes(command_id), 0, binding, &account).unwrap();
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
    .unwrap();
    let proof = NostrPrincipalControlProof::sign(payload, nostr_secret).unwrap();
    ProofBearingDeviceHandleClaim::new(root_claim, proof).unwrap()
}

#[tokio::test]
async fn daemon_service_serializes_verified_claim_and_all_lookup_keys() {
    let registry_directory = tempdir().unwrap();
    let daemon_directory = tempdir().unwrap();
    let registry_store = SealedStore::open(registry_directory.path(), RequestedProvider::File)
        .await
        .unwrap();
    let daemon_store = SealedStore::open(daemon_directory.path(), RequestedProvider::File)
        .await
        .unwrap();
    let mut registry = PrincipalRegistryService::open(&registry_store, [0x71; 32], None).unwrap();
    let pinned_key = registry.verifying_key();
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let endpoint = format!(
        "ws://{}/principal-registry-v1",
        listener.local_addr().unwrap()
    );
    let transport = RegistryWebSocketTransport::new(&endpoint).unwrap();
    let evidence =
        PrincipalRegistryEvidenceService::with_transport(transport, pinned_key, 100).unwrap();
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
        let handle = GlobalHandle::parse("alice").unwrap();
        let account_id = claim.claim().binding().account_id.clone();
        let public_key = claim.principal_proof().payload().nostr_public_key();
        assert!(matches!(
            evidence
                .claim_device(&daemon_store, &claim, 1_000)
                .await
                .unwrap(),
            PrincipalRegistryCacheLookup::Fresh(_)
        ));
        assert!(
            evidence
                .resolve_handle(&daemon_store, &handle, 1_001)
                .await
                .unwrap()
                .is_online()
        );
        assert!(
            evidence
                .resolve_public_key(&daemon_store, &public_key, 1_002)
                .await
                .unwrap()
                .is_online()
        );
        assert!(
            evidence
                .resolve_account(&daemon_store, &account_id, 1_003)
                .await
                .unwrap()
                .is_online()
        );
        assert!(matches!(
            evidence
                .cached_public_key(&daemon_store, &public_key, 1_004)
                .await
                .unwrap(),
            PrincipalRegistryCacheLookup::Fresh(_)
        ));
        shutdown_tx.send(()).unwrap();
    };
    let (report, ()) = tokio::join!(host, client);
    let report = report.unwrap();
    assert_eq!(report.admitted_connections, 4);
    assert_eq!(report.completed_responses, 4);
    assert!(!report.forced_shutdown);
}
