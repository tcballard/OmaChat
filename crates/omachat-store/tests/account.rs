use omachat_crypto::{
    AccountError, AccountSecrets, DisplayName, GlobalHandle, IdentitySecrets,
    SignedLocalAccountBinding,
};
use omachat_store::{
    AccountVault, AccountVaultError, IdentityVault, RequestedProvider, SealedStore,
};
use serde::Serialize;
use std::{fs, io::Cursor};
use tempfile::tempdir;
use zeroize::Zeroizing;

const MAX_TEST_ACCOUNT_RECORD_PLAINTEXT_BYTES: usize = 4 * 1024;

#[derive(Serialize)]
struct TestPersistedAccount<'account> {
    version: u16,
    secrets: &'account AccountSecrets,
    binding: &'account SignedLocalAccountBinding,
}

fn write_account_record(
    store: &SealedStore,
    secrets: &AccountSecrets,
    binding: &SignedLocalAccountBinding,
) {
    let mut encoded = Zeroizing::new([0_u8; MAX_TEST_ACCOUNT_RECORD_PLAINTEXT_BYTES]);
    let encoded_bytes = {
        let mut writer = Cursor::new(&mut encoded[..]);
        serde_json::to_writer(
            &mut writer,
            &TestPersistedAccount {
                version: 1,
                secrets,
                binding,
            },
        )
        .unwrap();
        usize::try_from(writer.position()).unwrap()
    };
    store
        .write("account-v1", &encoded[..encoded_bytes])
        .unwrap();
}

fn device_identity(seed: u8) -> IdentitySecrets {
    IdentitySecrets::from_all_seeds([seed; 32], [seed + 1; 32], [seed + 2; 32], [seed + 3; 32])
}

#[tokio::test]
async fn account_is_sealed_and_profile_survives_omitted_configuration() {
    let temporary = tempdir().unwrap();
    let store = SealedStore::open(temporary.path(), RequestedProvider::File)
        .await
        .unwrap();
    let identity = device_identity(10);
    let first = AccountVault::load_or_create(
        &store,
        &identity,
        Some(GlobalHandle::parse("tom_secure_profile_2026").unwrap()),
        Some(DisplayName::parse("Tom Ballard").unwrap()),
        100,
    )
    .unwrap();
    let account_id = first.public_identity().account_id;
    assert_eq!(first.binding().revision, 1);
    assert_eq!(
        first.binding().handle.as_ref().unwrap().as_str(),
        "tom_secure_profile_2026"
    );
    assert_eq!(
        first.binding().display_name.as_ref().unwrap().as_str(),
        "Tom Ballard"
    );
    first.binding().verify().unwrap();
    drop(first);

    let backing = fs::read(temporary.path().join("records/account-v1")).unwrap();
    assert!(
        !backing
            .windows("tom_secure_profile_2026".len())
            .any(|window| window == b"tom_secure_profile_2026")
    );
    assert!(
        !backing
            .windows("Tom Ballard".len())
            .any(|window| window == b"Tom Ballard")
    );

    let reopened = AccountVault::load_or_create(&store, &identity, None, None, 200).unwrap();
    assert_eq!(reopened.public_identity().account_id, account_id);
    assert_eq!(reopened.binding().revision, 1);
    assert_eq!(reopened.binding().issued_at, 100);
    assert_eq!(
        reopened.binding().handle.as_ref().unwrap().as_str(),
        "tom_secure_profile_2026"
    );
    assert_eq!(
        reopened.binding().display_name.as_ref().unwrap().as_str(),
        "Tom Ballard"
    );
}

#[tokio::test]
async fn explicit_profile_changes_increment_revision_and_preserve_omitted_fields() {
    let temporary = tempdir().unwrap();
    let store = SealedStore::open(temporary.path(), RequestedProvider::File)
        .await
        .unwrap();
    let identity = device_identity(20);
    AccountVault::load_or_create(
        &store,
        &identity,
        Some(GlobalHandle::parse("tom").unwrap()),
        Some(DisplayName::parse("Tom").unwrap()),
        100,
    )
    .unwrap();

    let renamed = AccountVault::load_or_create(
        &store,
        &identity,
        Some(GlobalHandle::parse("tom_2").unwrap()),
        None,
        200,
    )
    .unwrap();
    assert_eq!(renamed.binding().revision, 2);
    assert_eq!(renamed.binding().handle.as_ref().unwrap().as_str(), "tom_2");
    assert_eq!(
        renamed.binding().display_name.as_ref().unwrap().as_str(),
        "Tom"
    );
    drop(renamed);

    let redisplayed = AccountVault::load_or_create(
        &store,
        &identity,
        None,
        Some(DisplayName::parse("Thomas").unwrap()),
        300,
    )
    .unwrap();
    assert_eq!(redisplayed.binding().revision, 3);
    assert_eq!(
        redisplayed.binding().handle.as_ref().unwrap().as_str(),
        "tom_2"
    );
    assert_eq!(
        redisplayed
            .binding()
            .display_name
            .as_ref()
            .unwrap()
            .as_str(),
        "Thomas"
    );
    let signature = redisplayed.binding().signature;
    drop(redisplayed);

    let unchanged = AccountVault::load_or_create(
        &store,
        &identity,
        Some(GlobalHandle::parse("tom_2").unwrap()),
        Some(DisplayName::parse("Thomas").unwrap()),
        400,
    )
    .unwrap();
    assert_eq!(unchanged.binding().revision, 3);
    assert_eq!(unchanged.binding().issued_at, 300);
    assert_eq!(unchanged.binding().signature, signature);
}

#[tokio::test]
async fn malformed_or_mismatched_records_fail_closed_without_regeneration() {
    let temporary = tempdir().unwrap();
    let store = SealedStore::open(temporary.path(), RequestedProvider::File)
        .await
        .unwrap();
    let identity = device_identity(30);
    store.write("account-v1", b"not-json").unwrap();
    for _ in 0..2 {
        assert!(matches!(
            AccountVault::load_or_create(&store, &identity, None, None, 100),
            Err(AccountVaultError::Encoding)
        ));
    }

    store.delete("account-v1").unwrap();
    AccountVault::load_or_create(&store, &identity, None, None, 100).unwrap();
    let other_identity = device_identity(40);
    assert!(matches!(
        AccountVault::load_or_create(&store, &other_identity, None, None, 200),
        Err(AccountVaultError::DeviceIdentityMismatch)
    ));
}

#[tokio::test]
async fn invalid_binding_signature_and_secret_authority_mismatch_are_rejected() {
    let temporary = tempdir().unwrap();
    let store = SealedStore::open(temporary.path(), RequestedProvider::File)
        .await
        .unwrap();
    let identity = device_identity(50);
    let public = identity.public_identity();
    let nostr = identity.device_nostr_identity().unwrap();
    let device_keys = omachat_crypto::DevicePublicKeys {
        signing_public_key: public.signing_public_key,
        noise_public_key: public.noise_public_key,
        nostr_public_key: *nostr.public_key(),
    };
    let account_secrets = AccountSecrets::from_seeds([70; 32], [71; 32]);
    let mut binding = account_secrets.sign_local_binding(None, None, device_keys, 1, 100);
    binding.signature[0] ^= 1;
    write_account_record(&store, &account_secrets, &binding);
    assert!(matches!(
        AccountVault::load_or_create(&store, &identity, None, None, 200),
        Err(AccountVaultError::Account(AccountError::InvalidSignature))
    ));

    let other_secrets = AccountSecrets::from_seeds([72; 32], [73; 32]);
    let binding = AccountSecrets::from_seeds([74; 32], [75; 32]).sign_local_binding(
        None,
        None,
        device_keys,
        1,
        100,
    );
    write_account_record(&store, &other_secrets, &binding);
    assert!(matches!(
        AccountVault::load_or_create(&store, &identity, None, None, 200),
        Err(AccountVaultError::AccountAuthorityMismatch)
    ));
}

#[tokio::test]
async fn adding_an_account_does_not_change_the_existing_identity_record() {
    let temporary = tempdir().unwrap();
    let store = SealedStore::open(temporary.path(), RequestedProvider::File)
        .await
        .unwrap();
    let identity = IdentityVault::load_or_create(&store).unwrap();
    let before = identity.public_identity();
    AccountVault::load_or_create(&store, &identity, None, None, 100).unwrap();
    drop(identity);

    let reloaded = IdentityVault::load_or_create(&store).unwrap();
    assert_eq!(reloaded.public_identity(), before);
}
