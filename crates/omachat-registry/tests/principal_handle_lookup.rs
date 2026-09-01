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

fn nostr_public_key(secret: &[u8; 32]) -> [u8; 32] {
    SchnorrSigningKey::from_bytes(secret)
        .unwrap()
        .verifying_key()
        .to_bytes()
        .into()
}

fn claim(
    account: &AccountSecrets,
    nostr_secret: [u8; 32],
    command: u8,
    expected_revision: u64,
    binding_revision: u64,
) -> ProofBearingDeviceHandleClaim {
    let public_key = nostr_public_key(&nostr_secret);
    let binding = account.sign_local_binding(
        Some(GlobalHandle::parse("alice").unwrap()),
        Some(DisplayName::parse("Principal Handle Test").unwrap()),
        DevicePublicKeys {
            signing_public_key: AccountSecrets::from_seeds([command; 32], [command + 1; 32])
                .public_identity()
                .account_root_public_key,
            noise_public_key: [command + 2; 32],
            nostr_public_key: public_key,
        },
        binding_revision,
        1_788_000_000 + binding_revision,
    );
    let command_id = [command; 32];
    let root_claim = HandleClaim::sign(
        CommandId::from_bytes(command_id),
        expected_revision,
        binding,
        account,
    )
    .unwrap();
    let payload = NostrPrincipalControlPayload::new(
        root_claim.claim_hash(),
        command_id,
        expected_revision,
        root_claim.binding().account_id.as_str(),
        "alice",
        NostrPrincipalType::Device,
        public_key,
        device_authorisation_hash(root_claim.binding()),
        1_788_000_100 + binding_revision,
    )
    .unwrap();
    let proof = NostrPrincipalControlProof::sign(payload, nostr_secret).unwrap();
    ProofBearingDeviceHandleClaim::new(root_claim, proof).unwrap()
}

#[test]
fn canonical_handle_tracks_the_current_proven_principal() {
    let account = AccountSecrets::from_seeds([0x11; 32], [0x12; 32]);
    let handle = GlobalHandle::parse("alice").unwrap();
    let mut state = PrincipalRegistryState::from_signing_seed([0x71; 32]);
    let first = state
        .apply_device(claim(&account, [0x31; 32], 0x41, 0, 1), 1_788_000_200)
        .unwrap();
    assert_eq!(state.handle_record(&handle), Some(&first));

    let rotated = state
        .apply_device(claim(&account, [0x32; 32], 0x42, 1, 2), 1_788_000_201)
        .unwrap();
    assert_eq!(state.handle_record(&handle), Some(&rotated));
    assert!(
        state
            .handle_record(&GlobalHandle::parse("nobody").unwrap())
            .is_none()
    );
}
