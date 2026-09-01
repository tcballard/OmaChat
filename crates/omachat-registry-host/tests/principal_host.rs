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
use omachat_registry_transport::{
    PrincipalRegistryRequest, PrincipalRegistryResponseOutcome, PrincipalRegistryService,
    RegistryRequest, RegistryTransport, RegistryWebSocketTransport, decode_principal_response,
    encode_principal_request, encode_request,
};
use omachat_store::{RequestedProvider, SealedStore};
use tempfile::tempdir;
use tokio::{net::TcpListener, sync::oneshot};

fn nostr_public_key(secret: &[u8; 32]) -> [u8; 32] {
    SchnorrSigningKey::from_bytes(secret)
        .unwrap()
        .verifying_key()
        .to_bytes()
        .into()
}

fn validated_claim() -> ProofBearingDeviceHandleClaim {
    let account = AccountSecrets::from_seeds([0x11; 32], [0x12; 32]);
    let nostr_secret = [0x31; 32];
    let public_key = nostr_public_key(&nostr_secret);
    let device_signer = AccountSecrets::from_seeds([0x21; 32], [0x22; 32]);
    let binding = account.sign_local_binding(
        Some(GlobalHandle::parse("alice").unwrap()),
        Some(DisplayName::parse("Principal Host Test").unwrap()),
        DevicePublicKeys {
            signing_public_key: device_signer.public_identity().account_root_public_key,
            noise_public_key: [0x23; 32],
            nostr_public_key: public_key,
        },
        1,
        1_788_000_001,
    );
    let command_id = [0x41; 32];
    let claim = HandleClaim::sign(CommandId::from_bytes(command_id), 0, binding, &account).unwrap();
    let payload = NostrPrincipalControlPayload::new(
        claim.claim_hash(),
        command_id,
        0,
        claim.binding().account_id.as_str(),
        "alice",
        NostrPrincipalType::Device,
        public_key,
        device_authorisation_hash(claim.binding()),
        1_788_000_002,
    )
    .unwrap();
    let proof = NostrPrincipalControlProof::sign(payload, nostr_secret).unwrap();
    ProofBearingDeviceHandleClaim::new(claim, proof).unwrap()
}

#[tokio::test]
async fn principal_host_rejects_legacy_wire_then_serves_verified_principal_evidence() {
    let directory = tempdir().unwrap();
    let store = SealedStore::open(directory.path(), RequestedProvider::File)
        .await
        .unwrap();
    let mut service = PrincipalRegistryService::open(&store, [0x71; 32], None).unwrap();
    let pinned_key = service.verifying_key();
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let endpoint = format!(
        "ws://{}/principal-registry-v1",
        listener.local_addr().unwrap()
    );
    let (shutdown_tx, shutdown_rx) = oneshot::channel();
    let host = run_principal_registry_host(
        listener,
        &mut service,
        RegistryHostLimits::default(),
        || Ok(1_788_000_003),
        async {
            let _ = shutdown_rx.await;
        },
    );
    let client = async {
        let mut legacy_transport = RegistryWebSocketTransport::new(&endpoint).unwrap();
        let legacy = encode_request(&RegistryRequest::lookup_handle(
            1,
            GlobalHandle::parse("alice").unwrap(),
        ))
        .unwrap();
        assert!(legacy_transport.exchange(legacy).await.is_err());

        let claim = validated_claim();
        let public_key = claim.principal_proof().payload().nostr_public_key();
        let mut transport = RegistryWebSocketTransport::new(&endpoint).unwrap();
        let accepted = transport
            .exchange(
                encode_principal_request(&PrincipalRegistryRequest::claim_device(2, &claim))
                    .unwrap(),
            )
            .await
            .unwrap();
        let accepted = decode_principal_response(&accepted).unwrap();
        let PrincipalRegistryResponseOutcome::Accepted { record } = accepted.outcome else {
            panic!("valid principal claim must be accepted");
        };
        assert_eq!(record.verify(&pinned_key).unwrap().claim(), &claim);

        let found = transport
            .exchange(
                encode_principal_request(&PrincipalRegistryRequest::lookup_public_key(
                    3, public_key,
                ))
                .unwrap(),
            )
            .await
            .unwrap();
        let found = decode_principal_response(&found).unwrap();
        let PrincipalRegistryResponseOutcome::Found { record } = found.outcome else {
            panic!("accepted principal must resolve by public key");
        };
        assert_eq!(record.verify(&pinned_key).unwrap().claim(), &claim);
        shutdown_tx.send(()).unwrap();
    };

    let (report, ()) = tokio::join!(host, client);
    let report = report.unwrap();
    assert_eq!(report.admitted_connections, 3);
    assert_eq!(report.rejected_protocol_requests, 1);
    assert_eq!(report.completed_responses, 2);
    assert!(!report.forced_shutdown);
}
