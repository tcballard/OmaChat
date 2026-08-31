use omachat_crypto::{
    AccountSecrets, AgentAuthorizationRequest, DisplayName, SignedAgentAuthorization,
    SignedAgentRevocation,
};
use serde::Deserialize;
use std::{fs, path::PathBuf};

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Inputs {
    schema_version: u16,
    account_root_seed_hex: String,
    recovery_seed_hex: String,
    agent_secret_key_hex: String,
    agent_auxiliary_randomness_hex: String,
    label: String,
    requested_at: u64,
    authorization_revision: u64,
    authorized_at: u64,
    revocation_revision: u64,
    revoked_at: u64,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Intermediates {
    schema_version: u16,
    request_signing_bytes_hex: String,
    request_proof_digest_hex: String,
    authorization_signing_bytes_hex: String,
    revocation_signing_bytes_hex: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Outputs {
    schema_version: u16,
    account_id: String,
    account_root_public_key_hex: String,
    agent_public_key_hex: String,
    authorization_id: String,
    agent_proof_hex: String,
    authorization_signature_hex: String,
    authorization_hash_hex: String,
    revocation_signature_hex: String,
}

fn fixture_path(file_name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../conformance/fixtures/omachat-agent-authorization-v1")
        .join(file_name)
}

fn read_json<T: for<'de> Deserialize<'de>>(file_name: &str) -> T {
    serde_json::from_slice(&fs::read(fixture_path(file_name)).unwrap()).unwrap()
}

fn hex_array<const N: usize>(encoded: &str) -> [u8; N] {
    hex::decode(encoded).unwrap().try_into().unwrap()
}

#[test]
fn agent_lifecycle_matches_independent_python_transcripts() {
    let inputs: Inputs = read_json("inputs.json");
    let intermediates: Intermediates = read_json("intermediates.json");
    let outputs: Outputs = read_json("outputs.json");
    assert_eq!(inputs.schema_version, 1);
    assert_eq!(intermediates.schema_version, 1);
    assert_eq!(outputs.schema_version, 1);

    let owner = AccountSecrets::from_seeds(
        hex_array(&inputs.account_root_seed_hex),
        hex_array(&inputs.recovery_seed_hex),
    );
    let request = AgentAuthorizationRequest::sign(
        &hex_array(&inputs.agent_secret_key_hex),
        owner.public_identity().account_id,
        Some(DisplayName::parse(&inputs.label).unwrap()),
        inputs.requested_at,
        &hex_array(&inputs.agent_auxiliary_randomness_hex),
    )
    .unwrap();
    assert_eq!(
        owner.public_identity().account_id.as_str(),
        outputs.account_id
    );
    assert_eq!(
        owner.public_identity().account_root_public_key,
        hex_array(&outputs.account_root_public_key_hex)
    );
    assert_eq!(
        request.agent_public_key,
        hex_array(&outputs.agent_public_key_hex)
    );
    assert_eq!(
        request.signing_bytes(),
        hex::decode(&intermediates.request_signing_bytes_hex).unwrap()
    );
    assert_eq!(
        request.proof_digest(),
        hex_array(&intermediates.request_proof_digest_hex)
    );
    assert_eq!(request.agent_proof, hex_array(&outputs.agent_proof_hex));

    let authorization: SignedAgentAuthorization = owner
        .authorize_agent(request, inputs.authorization_revision, inputs.authorized_at)
        .unwrap();
    assert_eq!(
        authorization.authorization_id.as_str(),
        outputs.authorization_id
    );
    assert_eq!(
        authorization.signing_bytes(),
        hex::decode(&intermediates.authorization_signing_bytes_hex).unwrap()
    );
    assert_eq!(
        authorization.signature,
        hex_array(&outputs.authorization_signature_hex)
    );
    assert_eq!(
        authorization.authorization_hash(),
        hex_array(&outputs.authorization_hash_hex)
    );
    authorization.verify().unwrap();

    let revocation: SignedAgentRevocation = owner
        .revoke_agent(
            &authorization,
            inputs.revocation_revision,
            inputs.revoked_at,
        )
        .unwrap();
    assert_eq!(
        revocation.signing_bytes(),
        hex::decode(&intermediates.revocation_signing_bytes_hex).unwrap()
    );
    assert_eq!(
        revocation.signature,
        hex_array(&outputs.revocation_signature_hex)
    );
    revocation.verify(&authorization).unwrap();
}
