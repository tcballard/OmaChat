use omachat_crypto::{
    AccountSecrets, DevicePublicKeys, DisplayName, GlobalHandle, IdentitySecrets,
    SignedLocalAccountBinding,
};
use omachat_registry::{CommandId, HandleClaim, RegistryError, RegistryStateSnapshot};
use omachat_store::{RegistryVault, RegistryVaultError, RequestedProvider, SealedStore};
use serde_json::to_writer;
use std::io::Cursor;
use tempfile::tempdir;
use zeroize::Zeroizing;

const MAX_REGISTRY_RECORD_PLAINTEXT_BYTES: usize = 4 * 1024 * 1024;

fn account(seed: u8) -> AccountSecrets {
    AccountSecrets::from_seeds([seed; 32], [seed.wrapping_add(1); 32])
}

fn identity(seed: u8) -> IdentitySecrets {
    IdentitySecrets::from_all_seeds(
        [seed; 32],
        [seed.wrapping_add(1); 32],
        [seed.wrapping_add(2); 32],
        [seed.wrapping_add(3); 32],
    )
}

fn device_keys(seed: u8) -> DevicePublicKeys {
    let signing = account(seed).public_identity();
    let nostr = identity(seed).device_nostr_identity().unwrap();
    DevicePublicKeys {
        signing_public_key: signing.signing_public_key,
        noise_public_key: [seed.wrapping_add(30); 32],
        nostr_public_key: *nostr.public_key(),
    }
}

fn binding(account: &AccountSecrets, handle: &str, revision: u64) -> SignedLocalAccountBinding {
    account.sign_local_binding(
        Some(GlobalHandle::parse(handle).unwrap()),
        Some(DisplayName::parse("Registry Test").unwrap()),
        device_keys(revision as u8),
        revision,
        1_788_000_000 + revision,
    )
}

fn claim(
    account: &AccountSecrets,
    command: u8,
    handle: &str,
    expected_revision: u64,
) -> HandleClaim {
    HandleClaim::sign(
        CommandId::from_bytes([command; 32]),
        expected_revision,
        binding(account, handle, expected_revision + 1),
        account,
    )
    .unwrap()
}

fn write_snapshot(store: &SealedStore, snapshot: &RegistryStateSnapshot) {
    let mut encoded = Zeroizing::new([0_u8; MAX_REGISTRY_RECORD_PLAINTEXT_BYTES]);
    let encoded_bytes = {
        let mut writer = Cursor::new(&mut encoded[..]);
        to_writer(&mut writer, snapshot).unwrap();
        usize::try_from(writer.position()).unwrap()
    };
    store
        .write("registry-state-v1", &encoded[..encoded_bytes])
        .unwrap();
}

#[tokio::test]
async fn registry_state_survives_restart_with_idempotent_replay() {
    let temporary = tempdir().unwrap();
    let store = SealedStore::open(temporary.path(), RequestedProvider::File)
        .await
        .unwrap();

    let mut initial = RegistryVault::load_or_create(&store, [44; 32]).unwrap();
    let alice = account(1);
    let bob = account(3);

    let first_claim = claim(&alice, 1, "alice", 0);
    let bob_claim = claim(&bob, 2, "bob", 0);
    let alice_followup = claim(&alice, 3, "alice", 1);

    let first_receipt = initial.apply(first_claim.clone(), 100).unwrap();
    initial.apply(bob_claim, 101).unwrap();
    initial.apply(alice_followup, 102).unwrap();

    let expected_snapshot = initial.snapshot();
    RegistryVault::persist(&store, &initial).unwrap();

    let mut reloaded = RegistryVault::load_or_create(&store, [44; 32]).unwrap();
    assert_eq!(reloaded.snapshot(), expected_snapshot);

    let replayed = reloaded.apply(first_claim, 200).unwrap();
    assert_eq!(replayed, first_receipt);
    assert_eq!(reloaded.snapshot(), expected_snapshot);
}

#[tokio::test]
async fn malformed_and_unsupported_version_state_records_fail_closed() {
    let temporary = tempdir().unwrap();
    let store = SealedStore::open(temporary.path(), RequestedProvider::File)
        .await
        .unwrap();

    store.write("registry-state-v1", b"not-json").unwrap();
    assert!(matches!(
        RegistryVault::load_or_create(&store, [55; 32]),
        Err(RegistryVaultError::Encoding)
    ));

    store.delete("registry-state-v1").unwrap();
    let mut initial = RegistryVault::load_or_create(&store, [55; 32]).unwrap();
    initial
        .apply(claim(&account(2), 1, "alice", 0), 100)
        .unwrap();
    let mut unsupported = initial.snapshot();
    unsupported.version = 2;
    write_snapshot(&store, &unsupported);
    assert!(matches!(
        RegistryVault::load_or_create(&store, [55; 32]),
        Err(RegistryVaultError::UnsupportedVersion(2))
    ));
}

#[tokio::test]
async fn corrupted_state_records_are_rejected_without_mutation() {
    let temporary = tempdir().unwrap();
    let store = SealedStore::open(temporary.path(), RequestedProvider::File)
        .await
        .unwrap();

    let mut initial = RegistryVault::load_or_create(&store, [66; 32]).unwrap();
    initial
        .apply(claim(&account(8), 1, "alice", 0), 100)
        .unwrap();
    RegistryVault::persist(&store, &initial).unwrap();

    let mut rolled_back = initial.snapshot();
    let mut truncated = rolled_back.commands.clone();
    truncated.pop();
    rolled_back.commands = truncated;
    write_snapshot(&store, &rolled_back);
    let truncated_record = store.read("registry-state-v1").unwrap();
    assert!(matches!(
        RegistryVault::load_or_create(&store, [66; 32]),
        Err(RegistryVaultError::Registry(
            RegistryError::InvalidRegistryState
        ))
    ));
    assert_eq!(store.read("registry-state-v1").unwrap(), truncated_record);
}

#[tokio::test]
async fn tampered_receipt_signature_is_rejected_without_mutation() {
    let temporary = tempdir().unwrap();
    let store = SealedStore::open(temporary.path(), RequestedProvider::File)
        .await
        .unwrap();

    let mut initial = RegistryVault::load_or_create(&store, [77; 32]).unwrap();
    initial
        .apply(claim(&account(12), 1, "alice", 0), 100)
        .unwrap();
    RegistryVault::persist(&store, &initial).unwrap();

    let mut tampered = initial.snapshot();
    tampered.commands[0].receipt.signature[0] ^= 0xFF;
    write_snapshot(&store, &tampered);
    let tampered_record = store.read("registry-state-v1").unwrap();
    assert!(matches!(
        RegistryVault::load_or_create(&store, [77; 32]),
        Err(RegistryVaultError::Registry(
            RegistryError::InvalidReceiptSignature
        ))
    ));
    assert_eq!(store.read("registry-state-v1").unwrap(), tampered_record);
}

#[tokio::test]
async fn inconsistent_claim_hash_is_rejected() {
    let temporary = tempdir().unwrap();
    let store = SealedStore::open(temporary.path(), RequestedProvider::File)
        .await
        .unwrap();

    let mut initial = RegistryVault::load_or_create(&store, [88; 32]).unwrap();
    initial
        .apply(claim(&account(13), 1, "alice", 0), 100)
        .unwrap();
    RegistryVault::persist(&store, &initial).unwrap();

    let mut inconsistent = initial.snapshot();
    inconsistent.commands[0].claim_hash[0] ^= 0xFF;
    write_snapshot(&store, &inconsistent);
    let inconsistent_record = store.read("registry-state-v1").unwrap();
    assert!(matches!(
        RegistryVault::load_or_create(&store, [88; 32]),
        Err(RegistryVaultError::Registry(
            RegistryError::InvalidRegistryState
        ))
    ));
    assert_eq!(
        store.read("registry-state-v1").unwrap(),
        inconsistent_record
    );
}
