use std::fs;

use omachat_crypto::{
    AccountSecrets, AgentAuthorizationRequest, AgentLifecycleState, AgentLifecycleStatus,
};
use omachat_store::{RequestedProvider, SealedStore, StoreError};
use omachatd::{
    AGENT_LIFECYCLE_RECORD_NAME, SealedAgentLifecycle, SealedAgentLifecycleError,
    SealedAgentLifecycleState,
};
use tempfile::tempdir;

fn lifecycle(owner: &AccountSecrets) -> AgentLifecycleState {
    let request = AgentAuthorizationRequest::sign(
        &[0x31; 32],
        owner.public_identity().account_id,
        None,
        1_788_100_000,
        &[0x42; 32],
    )
    .expect("agent request");
    let authorization = owner
        .authorize_agent(request, 1, 1_788_100_001)
        .expect("agent authorization");
    let revocation = owner
        .revoke_agent(&authorization, 2, 1_788_100_100)
        .expect("agent revocation");
    let mut state = AgentLifecycleState::new(owner.public_identity().account_id);
    state
        .add_authorization(authorization)
        .expect("store authorization");
    state.add_revocation(revocation).expect("store revocation");
    state
}

#[tokio::test]
async fn sealed_agent_lifecycle_is_restart_stable_and_account_bound() {
    let directory = tempdir().expect("state directory");
    let owner = AccountSecrets::from_seeds([1; 32], [2; 32]);
    let expected_account = owner.public_identity().account_id;
    let lifecycle = lifecycle(&owner);
    let store = SealedStore::open(directory.path(), RequestedProvider::File)
        .await
        .expect("open store");
    SealedAgentLifecycle::new(&store)
        .save(&lifecycle)
        .expect("save lifecycle");
    drop(store);

    let reopened = SealedStore::open(directory.path(), RequestedProvider::File)
        .await
        .expect("reopen store");
    let SealedAgentLifecycleState::Loaded(loaded) = SealedAgentLifecycle::new(&reopened)
        .load(&expected_account)
        .expect("load lifecycle")
    else {
        panic!("agent lifecycle was missing after restart");
    };
    assert_eq!(loaded, lifecycle);
    assert_eq!(
        loaded.records().next().expect("agent").status(),
        AgentLifecycleStatus::Revoked
    );

    let other = AccountSecrets::from_seeds([3; 32], [4; 32]);
    assert!(matches!(
        SealedAgentLifecycle::new(&reopened).load(&other.public_identity().account_id),
        Err(SealedAgentLifecycleError::AccountMismatch)
    ));
}

#[tokio::test]
async fn ciphertext_and_signed_lifecycle_tampering_fail_closed() {
    let directory = tempdir().expect("state directory");
    let owner = AccountSecrets::from_seeds([1; 32], [2; 32]);
    let account_id = owner.public_identity().account_id;
    let lifecycle = lifecycle(&owner);
    let store = SealedStore::open(directory.path(), RequestedProvider::File)
        .await
        .expect("open store");
    let adapter = SealedAgentLifecycle::new(&store);
    adapter.save(&lifecycle).expect("save lifecycle");

    let record_path = directory
        .path()
        .join("records")
        .join(AGENT_LIFECYCLE_RECORD_NAME);
    let mut ciphertext = fs::read(&record_path).expect("read ciphertext");
    *ciphertext.last_mut().expect("non-empty ciphertext") ^= 1;
    fs::write(&record_path, ciphertext).expect("tamper ciphertext");
    assert!(matches!(
        adapter.load(&account_id),
        Err(SealedAgentLifecycleError::Store(StoreError::Authentication))
    ));

    let encoded = lifecycle.to_json().expect("lifecycle JSON");
    let tampered = String::from_utf8(encoded)
        .expect("UTF-8 JSON")
        .replace("1788100000", "1788100001");
    store
        .write(AGENT_LIFECYCLE_RECORD_NAME, tampered.as_bytes())
        .expect("seal tampered lifecycle");
    assert!(matches!(
        adapter.load(&account_id),
        Err(SealedAgentLifecycleError::Lifecycle(_))
    ));
}

#[tokio::test]
async fn clear_returns_an_explicit_missing_state() {
    let directory = tempdir().expect("state directory");
    let owner = AccountSecrets::from_seeds([1; 32], [2; 32]);
    let account_id = owner.public_identity().account_id;
    let lifecycle = lifecycle(&owner);
    let store = SealedStore::open(directory.path(), RequestedProvider::File)
        .await
        .expect("open store");
    let adapter = SealedAgentLifecycle::new(&store);
    adapter.save(&lifecycle).expect("save lifecycle");
    adapter.clear().expect("clear lifecycle");
    assert!(matches!(
        adapter.load(&account_id),
        Ok(SealedAgentLifecycleState::Missing)
    ));
}
