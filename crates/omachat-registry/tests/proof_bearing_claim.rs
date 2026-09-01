use k256::schnorr::SigningKey as SchnorrSigningKey;
use omachat_crypto::{AccountSecrets, DevicePublicKeys, DisplayName, GlobalHandle};
use omachat_registry::{
    CommandId, HandleClaim,
    principal_proof::{
        NostrPrincipalControlPayload, NostrPrincipalControlProof, NostrPrincipalType,
    },
    proof_bearing_claim::{
        ProofBearingClaimError, ProofBearingDeviceHandleClaim, device_authorisation_hash,
    },
};

const COMMAND_ID: [u8; 32] = [0x41; 32];
const EXPECTED_REVISION: u64 = 0;

#[derive(Clone)]
struct ProofFields {
    claim_hash: [u8; 32],
    command_id: [u8; 32],
    expected_revision: u64,
    account_id: String,
    handle: String,
    principal_type: NostrPrincipalType,
    nostr_public_key: [u8; 32],
    authorisation_hash: [u8; 32],
    created_at: u64,
}

struct Fixture {
    claim: HandleClaim,
    nostr_secret_key: [u8; 32],
    fields: ProofFields,
}

fn nostr_public_key(secret: &[u8; 32]) -> [u8; 32] {
    SchnorrSigningKey::from_bytes(secret)
        .unwrap()
        .verifying_key()
        .to_bytes()
        .into()
}

fn fixture() -> Fixture {
    let account = AccountSecrets::from_seeds([0x11; 32], [0x12; 32]);
    let device_signer = AccountSecrets::from_seeds([0x21; 32], [0x22; 32]);
    let nostr_secret_key = [0x31; 32];
    let binding = account.sign_local_binding(
        Some(GlobalHandle::parse("codextom").unwrap()),
        Some(DisplayName::parse("Codex").unwrap()),
        DevicePublicKeys {
            signing_public_key: device_signer.public_identity().account_root_public_key,
            noise_public_key: [0x42; 32],
            nostr_public_key: nostr_public_key(&nostr_secret_key),
        },
        1,
        100,
    );
    let claim = HandleClaim::sign(
        CommandId::from_bytes(COMMAND_ID),
        EXPECTED_REVISION,
        binding,
        &account,
    )
    .unwrap();
    let fields = ProofFields {
        claim_hash: claim.claim_hash(),
        command_id: COMMAND_ID,
        expected_revision: EXPECTED_REVISION,
        account_id: claim.binding().account_id.as_str().to_owned(),
        handle: claim.binding().handle.as_ref().unwrap().as_str().to_owned(),
        principal_type: NostrPrincipalType::Device,
        nostr_public_key: claim.binding().device_keys.nostr_public_key,
        authorisation_hash: device_authorisation_hash(claim.binding()),
        created_at: 101,
    };
    Fixture {
        claim,
        nostr_secret_key,
        fields,
    }
}

fn sign(fields: &ProofFields, secret: [u8; 32]) -> NostrPrincipalControlProof {
    let payload = NostrPrincipalControlPayload::new(
        fields.claim_hash,
        fields.command_id,
        fields.expected_revision,
        &fields.account_id,
        &fields.handle,
        fields.principal_type,
        fields.nostr_public_key,
        fields.authorisation_hash,
        fields.created_at,
    )
    .unwrap();
    NostrPrincipalControlProof::sign(payload, secret).unwrap()
}

#[test]
fn valid_device_proof_adds_key_control_without_replacing_root_authorship() {
    let fixture = fixture();
    let proof = sign(&fixture.fields, fixture.nostr_secret_key);
    let validated = ProofBearingDeviceHandleClaim::new(fixture.claim.clone(), proof).unwrap();

    assert_eq!(validated.claim(), &fixture.claim);
    assert_eq!(
        validated.principal_proof().payload().nostr_public_key(),
        fixture.claim.binding().device_keys.nostr_public_key
    );
    assert_ne!(
        fixture.claim.binding().account_root_public_key,
        fixture.claim.binding().device_keys.nostr_public_key
    );
}

#[test]
fn every_duplicated_claim_and_binding_field_must_match() {
    let fixture = fixture();

    let mut cases = Vec::new();

    let mut changed = fixture.fields.clone();
    changed.claim_hash[0] ^= 1;
    cases.push((changed, ProofBearingClaimError::ClaimHashMismatch));

    let mut changed = fixture.fields.clone();
    changed.command_id = [0x51; 32];
    cases.push((changed, ProofBearingClaimError::CommandIdMismatch));

    let mut changed = fixture.fields.clone();
    changed.expected_revision += 1;
    cases.push((changed, ProofBearingClaimError::ExpectedRevisionMismatch));

    let mut changed = fixture.fields.clone();
    changed.account_id = AccountSecrets::from_seeds([0x61; 32], [0x62; 32])
        .public_identity()
        .account_id
        .as_str()
        .to_owned();
    cases.push((changed, ProofBearingClaimError::AccountMismatch));

    let mut changed = fixture.fields.clone();
    changed.handle = "researchtom".to_owned();
    cases.push((changed, ProofBearingClaimError::HandleMismatch));

    let mut changed = fixture.fields.clone();
    changed.principal_type = NostrPrincipalType::Agent;
    cases.push((changed, ProofBearingClaimError::PrincipalTypeMismatch));

    let mut changed = fixture.fields.clone();
    changed.authorisation_hash[0] ^= 1;
    cases.push((changed, ProofBearingClaimError::AuthorisationHashMismatch));

    let mut changed = fixture.fields.clone();
    changed.created_at = fixture.claim.binding().issued_at - 1;
    cases.push((changed, ProofBearingClaimError::ProofPredatesAuthorisation));

    for (fields, expected) in cases {
        let proof = sign(&fields, fixture.nostr_secret_key);
        assert_eq!(
            ProofBearingDeviceHandleClaim::new(fixture.claim.clone(), proof).unwrap_err(),
            expected
        );
    }
}

#[test]
fn another_valid_nostr_key_cannot_prove_the_bound_device() {
    let fixture = fixture();
    let other_secret = [0x71; 32];
    let mut fields = fixture.fields.clone();
    fields.nostr_public_key = nostr_public_key(&other_secret);
    let proof = sign(&fields, other_secret);

    assert_eq!(
        ProofBearingDeviceHandleClaim::new(fixture.claim, proof).unwrap_err(),
        ProofBearingClaimError::NostrPublicKeyMismatch
    );
}
