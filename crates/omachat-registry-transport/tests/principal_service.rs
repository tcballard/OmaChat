use k256::schnorr::SigningKey as SchnorrSigningKey;
use omachat_crypto::{AccountSecrets, DevicePublicKeys, DisplayName, GlobalHandle};
use omachat_registry::{
    CommandId, HandleClaim,
    principal_proof::{
        NostrPrincipalControlPayload, NostrPrincipalControlProof, NostrPrincipalType,
    },
    proof_bearing_claim::{ProofBearingDeviceHandleClaim, device_authorisation_hash},
};
use omachat_registry_transport::{
    PRINCIPAL_REGISTRY_TRANSPORT_VERSION, PrincipalRegistryOperation,
    PrincipalRegistryProtocolError, PrincipalRegistryRemoteCode, PrincipalRegistryRequest,
    PrincipalRegistryResponse, PrincipalRegistryResponseOutcome, PrincipalRegistryService,
    PrincipalRegistryServiceError, decode_principal_response, encode_principal_request,
};
use omachat_store::{RequestedProvider, SealedStore};
use tempfile::tempdir;

fn nostr_public_key(secret: &[u8; 32]) -> [u8; 32] {
    SchnorrSigningKey::from_bytes(secret)
        .unwrap()
        .verifying_key()
        .to_bytes()
        .into()
}

fn validated_claim(
    account_seed: u8,
    nostr_secret: [u8; 32],
    command: u8,
    handle: &str,
) -> ProofBearingDeviceHandleClaim {
    let account = AccountSecrets::from_seeds([account_seed; 32], [account_seed + 1; 32]);
    let public_key = nostr_public_key(&nostr_secret);
    let device_signer = AccountSecrets::from_seeds([account_seed + 2; 32], [account_seed + 3; 32]);
    let binding = account.sign_local_binding(
        Some(GlobalHandle::parse(handle).unwrap()),
        Some(DisplayName::parse("Principal Service Test").unwrap()),
        DevicePublicKeys {
            signing_public_key: device_signer.public_identity().account_root_public_key,
            noise_public_key: [account_seed + 4; 32],
            nostr_public_key: public_key,
        },
        1,
        1_788_000_001,
    );
    let command_id = [command; 32];
    let claim = HandleClaim::sign(CommandId::from_bytes(command_id), 0, binding, &account).unwrap();
    let payload = NostrPrincipalControlPayload::new(
        claim.claim_hash(),
        command_id,
        0,
        claim.binding().account_id.as_str(),
        handle,
        NostrPrincipalType::Device,
        public_key,
        device_authorisation_hash(claim.binding()),
        1_788_000_002,
    )
    .unwrap();
    let proof = NostrPrincipalControlProof::sign(payload, nostr_secret).unwrap();
    ProofBearingDeviceHandleClaim::new(claim, proof).unwrap()
}

fn response(
    service: &mut PrincipalRegistryService<'_>,
    request: &PrincipalRegistryRequest,
    accepted_at: u64,
) -> PrincipalRegistryResponse {
    let encoded = encode_principal_request(request).unwrap();
    decode_principal_response(&service.handle(&encoded, accepted_at).unwrap()).unwrap()
}

#[tokio::test]
async fn accepted_principal_is_durable_idempotent_and_queryable_after_restart() {
    let directory = tempdir().unwrap();
    let store = SealedStore::open(directory.path(), RequestedProvider::File)
        .await
        .unwrap();
    let claim = validated_claim(0x11, [0x31; 32], 0x41, "alice");
    let public_key = claim.principal_proof().payload().nostr_public_key();
    let account_id = claim.claim().binding().account_id.clone();
    let request = PrincipalRegistryRequest::claim_device(1, &claim);
    let pinned_key;
    let accepted;
    let head;

    {
        let mut service = PrincipalRegistryService::open(&store, [0x71; 32], None).unwrap();
        pinned_key = service.verifying_key();
        accepted = response(&mut service, &request, 1_788_000_003);
        head = service.head().clone();
        let PrincipalRegistryResponseOutcome::Accepted { record } = &accepted.outcome else {
            panic!("valid proof-bearing claim must be accepted");
        };
        assert_eq!(record.verify(&pinned_key).unwrap().claim(), &claim);
    }

    let mut restarted = PrincipalRegistryService::open(&store, [0x71; 32], Some(&head)).unwrap();
    assert_eq!(response(&mut restarted, &request, 1_788_000_099), accepted);
    assert_eq!(restarted.head(), &head);

    let by_public_key = response(
        &mut restarted,
        &PrincipalRegistryRequest::lookup_public_key(2, public_key),
        1_788_000_100,
    );
    let PrincipalRegistryResponseOutcome::Found { record } = by_public_key.outcome else {
        panic!("persisted public key must resolve");
    };
    assert_eq!(record.verify(&pinned_key).unwrap().claim(), &claim);

    let by_account = response(
        &mut restarted,
        &PrincipalRegistryRequest::lookup_account(3, account_id),
        1_788_000_101,
    );
    let PrincipalRegistryResponseOutcome::Found { record } = by_account.outcome else {
        panic!("persisted account must resolve");
    };
    assert_eq!(record.verify(&pinned_key).unwrap().claim(), &claim);
}

#[tokio::test]
async fn duplicate_public_key_is_rejected_without_mutating_the_accepted_binding() {
    let directory = tempdir().unwrap();
    let store = SealedStore::open(directory.path(), RequestedProvider::File)
        .await
        .unwrap();
    let alice = validated_claim(0x11, [0x31; 32], 0x41, "alice");
    let attacker = validated_claim(0x21, [0x31; 32], 0x42, "mallory");
    let public_key = alice.principal_proof().payload().nostr_public_key();
    let mut service = PrincipalRegistryService::open(&store, [0x71; 32], None).unwrap();
    let pinned_key = service.verifying_key();
    response(
        &mut service,
        &PrincipalRegistryRequest::claim_device(1, &alice),
        1_788_000_003,
    );
    let accepted_head = service.head().clone();

    let rejected = response(
        &mut service,
        &PrincipalRegistryRequest::claim_device(2, &attacker),
        1_788_000_004,
    );
    assert!(matches!(
        rejected.outcome,
        PrincipalRegistryResponseOutcome::Rejected { error }
            if error.code == PrincipalRegistryRemoteCode::PublicKeyTaken
    ));
    assert_eq!(service.head(), &accepted_head);

    let lookup = response(
        &mut service,
        &PrincipalRegistryRequest::lookup_public_key(3, public_key),
        1_788_000_005,
    );
    let PrincipalRegistryResponseOutcome::Found { record } = lookup.outcome else {
        panic!("original binding must remain live");
    };
    assert_eq!(record.verify(&pinned_key).unwrap().claim(), &alice);
}

#[tokio::test]
async fn malformed_proof_and_mismatched_external_head_fail_closed() {
    let directory = tempdir().unwrap();
    let store = SealedStore::open(directory.path(), RequestedProvider::File)
        .await
        .unwrap();
    let claim = validated_claim(0x11, [0x31; 32], 0x41, "alice");
    let mut request = PrincipalRegistryRequest::claim_device(1, &claim);
    let PrincipalRegistryOperation::ClaimDevice { claim } = &mut request.operation else {
        unreachable!();
    };
    *claim.principal_proof.last_mut().unwrap() ^= 1;
    let mut service = PrincipalRegistryService::open(&store, [0x71; 32], None).unwrap();
    let error = service
        .handle(&encode_principal_request(&request).unwrap(), 1_788_000_003)
        .unwrap_err();
    assert!(matches!(
        error,
        PrincipalRegistryServiceError::Protocol(PrincipalRegistryProtocolError::InvalidClaim)
    ));
    assert_eq!(service.head().entry_count, 0);

    let valid = validated_claim(0x11, [0x31; 32], 0x41, "alice");
    response(
        &mut service,
        &PrincipalRegistryRequest::claim_device(2, &valid),
        1_788_000_004,
    );
    let mut wrong_head = service.head().clone();
    wrong_head.entry_count += 1;
    drop(service);
    assert!(matches!(
        PrincipalRegistryService::open(&store, [0x71; 32], Some(&wrong_head)),
        Err(PrincipalRegistryServiceError::Persistence(_))
    ));
}

#[tokio::test]
async fn unknown_principal_lookup_is_explicitly_not_found() {
    let directory = tempdir().unwrap();
    let store = SealedStore::open(directory.path(), RequestedProvider::File)
        .await
        .unwrap();
    let mut service = PrincipalRegistryService::open(&store, [0x71; 32], None).unwrap();
    let not_found = response(
        &mut service,
        &PrincipalRegistryRequest {
            version: PRINCIPAL_REGISTRY_TRANSPORT_VERSION,
            request_id: 1,
            operation: PrincipalRegistryOperation::LookupPublicKey {
                nostr_public_key: nostr_public_key(&[0x31; 32]),
            },
        },
        1_788_000_003,
    );
    assert_eq!(
        not_found.outcome,
        PrincipalRegistryResponseOutcome::NotFound
    );
}
