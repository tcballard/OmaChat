use omachat_crypto::{
    AccountError, AccountId, AccountSecrets, DeviceId, DevicePublicKeys, DisplayName, GlobalHandle,
    IdentitySecrets,
};

fn device_keys() -> DevicePublicKeys {
    let device = AccountSecrets::from_seeds([3; 32], [4; 32]).public_identity();
    let nostr = IdentitySecrets::from_seeds([7; 32], [8; 32], [9; 32])
        .device_nostr_identity()
        .unwrap();
    DevicePublicKeys {
        signing_public_key: device.account_root_public_key,
        noise_public_key: [5; 32],
        nostr_public_key: *nostr.public_key(),
    }
}

#[test]
fn handles_are_canonical_and_strict() {
    assert_eq!(GlobalHandle::parse("@tom").unwrap().as_str(), "tom");
    assert_eq!(GlobalHandle::parse("tom_42").unwrap().as_str(), "tom_42");

    for invalid in [
        "to",
        "Tom",
        "2tom",
        "tom-ballard",
        "@@tom",
        "töm",
        "tom ",
        "this_handle_is_more_than_thirty_two_characters",
    ] {
        assert_eq!(
            GlobalHandle::parse(invalid),
            Err(AccountError::InvalidHandle),
            "accepted {invalid:?}"
        );
    }
}

#[test]
fn display_names_are_bounded_human_text() {
    assert_eq!(
        DisplayName::parse("Tom Ballard").unwrap().as_str(),
        "Tom Ballard"
    );
    assert!(DisplayName::parse(&"🙂".repeat(64)).is_ok());
    for invalid in [
        "".to_owned(),
        " Tom".to_owned(),
        "Tom\nBallard".to_owned(),
        "Tom\u{202e}Ballard".to_owned(),
        "T\u{200b}om".to_owned(),
        "x".repeat(81),
    ] {
        assert_eq!(
            DisplayName::parse(&invalid),
            Err(AccountError::InvalidDisplayName)
        );
    }
}

#[test]
fn account_and_device_ids_are_stable_and_domain_separated() {
    let public = AccountSecrets::from_seeds([1; 32], [2; 32]).public_identity();
    assert_eq!(
        public.account_id.as_str(),
        "oa1_1919c0ff904bd4d0ab100049c182672c51d4f481b78cd1378f631b058e2e1bc9"
    );
    let device_id = DeviceId::derive(&public.account_id, &[3; 32]);
    assert_eq!(
        device_id.as_str(),
        "od1_775cb97b11a4f29de0461750e912c6a01afb6fb647794a5a5add6a1a430e1866"
    );
    assert_eq!(
        AccountId::parse(public.account_id.as_str()).unwrap(),
        public.account_id
    );
    assert_eq!(DeviceId::parse(device_id.as_str()).unwrap(), device_id);
    assert!(AccountId::parse(&device_id.to_string().replace("od1_", "oa1_")).is_ok());
    assert_eq!(
        AccountId::parse("oa1_F6493F910E83AF4CE59C51ED5D1B431BFE7EB3204D323B4FA9CD72033A65B2BB"),
        Err(AccountError::InvalidAccountId)
    );
}

#[test]
fn configured_and_unconfigured_local_bindings_verify_publicly() {
    let secrets = AccountSecrets::from_seeds([1; 32], [2; 32]);
    let keys = device_keys();
    let configured = secrets.sign_local_binding(
        Some(GlobalHandle::parse("@tom").unwrap()),
        Some(DisplayName::parse("Tom Ballard").unwrap()),
        keys,
        7,
        1_788_000_000,
    );
    configured.verify().expect("valid configured binding");
    assert!(
        configured
            .signing_bytes()
            .starts_with(b"omachat.local-account-binding.v1\0")
    );
    assert_eq!(configured.signing_bytes(), configured.signing_bytes());

    let unconfigured = secrets.sign_local_binding(None, None, keys, 1, 1_788_000_000);
    unconfigured.verify().expect("valid device-only binding");
    assert!(unconfigured.handle.is_none());
    assert!(unconfigured.display_name.is_none());
    assert_ne!(configured.signing_bytes(), unconfigured.signing_bytes());
}

#[test]
fn binding_rejects_reused_recovery_authority_and_zero_revision() {
    let reused = AccountSecrets::from_seeds([1; 32], [1; 32]).sign_local_binding(
        None,
        None,
        device_keys(),
        1,
        1_788_000_000,
    );
    assert_eq!(reused.verify(), Err(AccountError::RecoveryAuthorityReuse));

    let mut zero_revision = AccountSecrets::from_seeds([1; 32], [2; 32]).sign_local_binding(
        None,
        None,
        device_keys(),
        1,
        1_788_000_000,
    );
    zero_revision.revision = 0;
    assert_eq!(
        zero_revision.verify(),
        Err(AccountError::InvalidBindingRevision)
    );
}

#[test]
fn binding_verification_rejects_tampering() {
    let secrets = AccountSecrets::from_seeds([1; 32], [2; 32]);
    let binding = secrets.sign_local_binding(
        Some(GlobalHandle::parse("tom").unwrap()),
        Some(DisplayName::parse("Tom").unwrap()),
        device_keys(),
        1,
        1_788_000_000,
    );

    let mut changed_handle = binding.clone();
    changed_handle.handle = Some(GlobalHandle::parse("tim").unwrap());
    assert_eq!(changed_handle.verify(), Err(AccountError::InvalidSignature));

    let mut changed_key = binding.clone();
    changed_key.device_keys.signing_public_key = [9; 32];
    assert_eq!(changed_key.verify(), Err(AccountError::DeviceIdMismatch));

    let mut changed_account = binding.clone();
    changed_account.account_root_public_key = [9; 32];
    assert_eq!(
        changed_account.verify(),
        Err(AccountError::AccountIdMismatch)
    );

    let mut changed_signature = binding;
    changed_signature.signature[0] ^= 1;
    assert_eq!(
        changed_signature.verify(),
        Err(AccountError::InvalidSignature)
    );
}

#[test]
fn serde_preserves_strict_validated_public_types() {
    let secrets = AccountSecrets::from_seeds([1; 32], [2; 32]);
    let binding = secrets.sign_local_binding(
        Some(GlobalHandle::parse("tom").unwrap()),
        Some(DisplayName::parse("Tom Ballard").unwrap()),
        device_keys(),
        1,
        1_788_000_000,
    );
    let encoded = serde_json::to_vec(&binding).unwrap();
    let decoded = serde_json::from_slice::<omachat_crypto::SignedLocalAccountBinding>(&encoded)
        .expect("strict binding JSON");
    assert_eq!(decoded, binding);
    decoded.verify().expect("round-trip signature");

    assert!(serde_json::from_str::<GlobalHandle>("\"Tom\"").is_err());
    assert!(serde_json::from_str::<AccountId>("\"oa1_00\"").is_err());
}
