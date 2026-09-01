use k256::schnorr::SigningKey as SchnorrSigningKey;
use omachat_crypto::{AccountSecrets, DevicePublicKeys, DisplayName, GlobalHandle};
use omachat_registry::{
    CommandId, HandleClaim,
    principal_proof::{
        NostrPrincipalControlPayload, NostrPrincipalControlProof, NostrPrincipalType,
    },
    principal_registry::PrincipalRegistryState,
    proof_bearing_claim::{ProofBearingDeviceHandleClaim, device_authorisation_hash},
};
use omachat_registry_transport::{
    MAX_PRINCIPAL_REGISTRY_MESSAGE_BYTES, PRINCIPAL_REGISTRY_TRANSPORT_VERSION,
    PrincipalRegistryClaim, PrincipalRegistryOperation, PrincipalRegistryProtocolError,
    PrincipalRegistryRecordWire, PrincipalRegistryRequest, PrincipalRegistryResponse,
    PrincipalRegistryResponseOutcome, decode_principal_request, decode_principal_response,
    encode_principal_request, encode_principal_response,
};

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
    let nostr_public_key = nostr_public_key(&nostr_secret);
    let binding = account.sign_local_binding(
        Some(GlobalHandle::parse(handle).unwrap()),
        Some(DisplayName::parse("Principal Transport Test").unwrap()),
        DevicePublicKeys {
            signing_public_key: test_account(account_seed + 4)
                .public_identity()
                .account_root_public_key,
            noise_public_key: [account_seed + 5; 32],
            nostr_public_key,
        },
        1,
        1_788_000_001,
    );
    let claim =
        HandleClaim::sign(CommandId::from_bytes([command; 32]), 0, binding, &account).unwrap();
    let payload = NostrPrincipalControlPayload::new(
        claim.claim_hash(),
        [command; 32],
        0,
        claim.binding().account_id.as_str(),
        handle,
        NostrPrincipalType::Device,
        nostr_public_key,
        device_authorisation_hash(claim.binding()),
        1_788_000_002,
    )
    .unwrap();
    let proof = NostrPrincipalControlProof::sign(payload, nostr_secret).unwrap();
    ProofBearingDeviceHandleClaim::new(claim, proof).unwrap()
}

fn test_account(seed: u8) -> AccountSecrets {
    AccountSecrets::from_seeds([seed; 32], [seed + 1; 32])
}

#[test]
fn proof_bearing_request_round_trips_and_rejects_invalid_nested_evidence() {
    let claim = validated_claim(0x11, [0x31; 32], 0x41, "alice");
    let request = PrincipalRegistryRequest::claim_device(7, &claim);
    let encoded = encode_principal_request(&request).unwrap();
    assert_eq!(decode_principal_request(&encoded).unwrap(), request);

    let PrincipalRegistryOperation::ClaimDevice { claim: wire_claim } = request.operation else {
        panic!("claim constructor must produce a claim operation");
    };
    assert_eq!(wire_claim.to_claim().unwrap(), claim);

    let mut corrupted = (*wire_claim).clone();
    *corrupted.principal_proof.last_mut().unwrap() ^= 1;
    let corrupted_request = PrincipalRegistryRequest {
        version: PRINCIPAL_REGISTRY_TRANSPORT_VERSION,
        request_id: 8,
        operation: PrincipalRegistryOperation::ClaimDevice {
            claim: Box::new(corrupted),
        },
    };
    assert_eq!(
        decode_principal_request(&encode_principal_request(&corrupted_request).unwrap()),
        Err(PrincipalRegistryProtocolError::InvalidClaim)
    );

    let mut unsupported = PrincipalRegistryClaim::from_claim(&claim);
    unsupported.version += 1;
    let unsupported_request = PrincipalRegistryRequest {
        version: PRINCIPAL_REGISTRY_TRANSPORT_VERSION,
        request_id: 9,
        operation: PrincipalRegistryOperation::ClaimDevice {
            claim: Box::new(unsupported),
        },
    };
    assert_eq!(
        decode_principal_request(&encode_principal_request(&unsupported_request).unwrap()),
        Err(PrincipalRegistryProtocolError::UnsupportedClaimVersion(2))
    );
}

#[test]
fn principal_record_round_trips_and_verifies_both_receipts() {
    let claim = validated_claim(0x11, [0x31; 32], 0x41, "alice");
    let mut registry = PrincipalRegistryState::from_signing_seed([0x71; 32]);
    let record = registry.apply_device(claim.clone(), 1_788_000_003).unwrap();
    let wire_record = PrincipalRegistryRecordWire::from_record(&record);
    let response = PrincipalRegistryResponse {
        version: PRINCIPAL_REGISTRY_TRANSPORT_VERSION,
        request_id: 7,
        outcome: PrincipalRegistryResponseOutcome::Accepted {
            record: Box::new(wire_record),
        },
    };
    let decoded =
        decode_principal_response(&encode_principal_response(&response).unwrap()).unwrap();
    let PrincipalRegistryResponseOutcome::Accepted {
        record: decoded_record,
    } = decoded.outcome
    else {
        panic!("accepted response must retain its outcome");
    };
    let verified = decoded_record.verify(&registry.verifying_key()).unwrap();
    assert_eq!(verified.claim(), &claim);
    assert_eq!(verified.claim_receipt(), record.claim_receipt());
    assert_eq!(verified.principal_receipt(), record.principal_receipt());
}

#[test]
fn principal_record_rejects_forged_and_cross_claim_receipts() {
    let alice = validated_claim(0x11, [0x31; 32], 0x41, "alice");
    let bob = validated_claim(0x21, [0x32; 32], 0x42, "bob");
    let mut trusted = PrincipalRegistryState::from_signing_seed([0x71; 32]);
    let alice_record = trusted.apply_device(alice.clone(), 1_788_000_003).unwrap();
    let bob_record = trusted.apply_device(bob, 1_788_000_004).unwrap();
    let trusted_key = trusted.verifying_key();

    let mut hostile = PrincipalRegistryState::from_signing_seed([0x72; 32]);
    let forged = hostile.apply_device(alice, 1_788_000_003).unwrap();
    assert_eq!(
        PrincipalRegistryRecordWire::from_record(&forged).verify(&trusted_key),
        Err(PrincipalRegistryProtocolError::InvalidEvidence)
    );

    let mut mismatched = PrincipalRegistryRecordWire::from_record(&alice_record);
    mismatched.principal_receipt = bob_record.principal_receipt().to_bytes();
    assert_eq!(
        mismatched.verify(&trusted_key),
        Err(PrincipalRegistryProtocolError::InvalidEvidence)
    );
}

#[test]
fn lookup_and_message_boundaries_are_explicit() {
    let claim = validated_claim(0x11, [0x31; 32], 0x41, "alice");
    let public_key = claim.principal_proof().payload().nostr_public_key();
    let account_id = claim.claim().binding().account_id.clone();
    let public_key_lookup = PrincipalRegistryRequest::lookup_public_key(1, public_key);
    let account_lookup = PrincipalRegistryRequest::lookup_account(2, account_id);
    assert_eq!(
        decode_principal_request(&encode_principal_request(&public_key_lookup).unwrap()).unwrap(),
        public_key_lookup
    );
    assert_eq!(
        decode_principal_request(&encode_principal_request(&account_lookup).unwrap()).unwrap(),
        account_lookup
    );

    let mut unknown_field = serde_json::to_value(public_key_lookup).unwrap();
    unknown_field["unexpected"] = serde_json::json!(true);
    assert_eq!(
        decode_principal_request(&serde_json::to_vec(&unknown_field).unwrap()),
        Err(PrincipalRegistryProtocolError::Malformed)
    );
    assert_eq!(
        decode_principal_request(&vec![0; MAX_PRINCIPAL_REGISTRY_MESSAGE_BYTES + 1]),
        Err(PrincipalRegistryProtocolError::MessageTooLarge)
    );
    let wrong_version = PrincipalRegistryRequest {
        version: PRINCIPAL_REGISTRY_TRANSPORT_VERSION + 1,
        request_id: 3,
        operation: PrincipalRegistryOperation::LookupPublicKey {
            nostr_public_key: public_key,
        },
    };
    assert_eq!(
        decode_principal_request(&encode_principal_request(&wrong_version).unwrap()),
        Err(PrincipalRegistryProtocolError::UnsupportedVersion(2))
    );
}
