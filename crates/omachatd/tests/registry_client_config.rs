use std::fs;

use ed25519_dalek::SigningKey;
use omachatd::DaemonConfig;
use tempfile::tempdir;

fn registry_key_hex(seed: u8) -> String {
    hex::encode(
        SigningKey::from_bytes(&[seed; 32])
            .verifying_key()
            .to_bytes(),
    )
}

fn load_json(value: serde_json::Value) -> Result<DaemonConfig, omachatd::CoreError> {
    let directory = tempdir().expect("config directory");
    let path = directory.path().join("config.json");
    fs::write(&path, serde_json::to_vec(&value).expect("config JSON")).expect("write config");
    DaemonConfig::load(path)
}

#[test]
fn registry_configuration_is_optional_and_explicit() {
    let unconfigured = load_json(serde_json::json!({})).expect("unconfigured daemon");
    assert!(unconfigured.registry.is_none());

    let configured = load_json(serde_json::json!({
        "registry": {
            "endpoint": "wss://registry.omachat.example/registry-v1",
            "pinned_public_key": registry_key_hex(7),
            "max_age_seconds": 86_400
        }
    }))
    .expect("configured daemon");
    let registry = configured.registry.expect("registry block");
    assert_eq!(
        registry.endpoint,
        "wss://registry.omachat.example/registry-v1"
    );
    assert_eq!(registry.max_age_seconds, 86_400);
    assert_eq!(
        registry.pinned_public_key_bytes().expect("pinned key"),
        SigningKey::from_bytes(&[7; 32]).verifying_key().to_bytes()
    );
}

#[test]
fn loopback_plaintext_is_allowed_but_remote_plaintext_is_rejected() {
    assert!(
        load_json(serde_json::json!({
            "registry": {
                "endpoint": "ws://127.0.0.1:8081/registry-v1",
                "pinned_public_key": registry_key_hex(8),
                "max_age_seconds": 60
            }
        }))
        .is_ok()
    );
    assert!(
        load_json(serde_json::json!({
            "registry": {
                "endpoint": "ws://registry.omachat.example/registry-v1",
                "pinned_public_key": registry_key_hex(8),
                "max_age_seconds": 60
            }
        }))
        .is_err()
    );
}

#[test]
fn registry_endpoint_cannot_carry_ambient_credentials_or_parameters() {
    for endpoint in [
        "wss://user@registry.omachat.example/registry-v1",
        "wss://registry.omachat.example/registry-v1?key=other",
        "wss://registry.omachat.example/registry-v1#other",
    ] {
        assert!(
            load_json(serde_json::json!({
                "registry": {
                    "endpoint": endpoint,
                    "pinned_public_key": registry_key_hex(9),
                    "max_age_seconds": 60
                }
            }))
            .is_err(),
            "accepted unsafe endpoint {endpoint}"
        );
    }
}

#[test]
fn registry_key_and_freshness_fail_closed() {
    for (pinned_public_key, max_age_seconds) in [
        ("00".repeat(31), 60),
        ("zz".repeat(32), 60),
        ("00".repeat(32), 60),
        (registry_key_hex(10), 0),
    ] {
        assert!(
            load_json(serde_json::json!({
                "registry": {
                    "endpoint": "wss://registry.omachat.example/registry-v1",
                    "pinned_public_key": pinned_public_key,
                    "max_age_seconds": max_age_seconds
                }
            }))
            .is_err()
        );
    }
}

#[test]
fn incomplete_or_extended_registry_blocks_are_rejected() {
    assert!(
        load_json(serde_json::json!({
            "registry": {
                "endpoint": "wss://registry.omachat.example/registry-v1",
                "pinned_public_key": registry_key_hex(11)
            }
        }))
        .is_err()
    );
    assert!(
        load_json(serde_json::json!({
            "registry": {
                "endpoint": "wss://registry.omachat.example/registry-v1",
                "pinned_public_key": registry_key_hex(11),
                "max_age_seconds": 60,
                "trust_endpoint_certificate": true
            }
        }))
        .is_err()
    );
}
