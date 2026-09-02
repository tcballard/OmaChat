use omachatd::DaemonConfig;
use serde_json::{Value, json};
use tempfile::tempdir;

fn load(value: Value) -> Result<DaemonConfig, omachatd::CoreError> {
    let directory = tempdir().expect("config directory");
    let path = directory.path().join("omachat.json");
    std::fs::write(&path, serde_json::to_vec(&value).expect("config JSON")).expect("write config");
    DaemonConfig::load(path)
}

#[test]
fn profile_publication_is_disabled_unless_explicitly_configured() {
    let config = load(json!({})).expect("default config");
    assert!(config.profile_publication.is_none());
}

#[test]
fn profile_relays_and_quorum_are_explicit_and_ordered() {
    let config = load(json!({
        "profile_publication": {
            "relays": [
                "wss://relay.omachat.example/",
                "wss://community.example/nostr",
                "ws://127.0.0.1:7447/"
            ],
            "required_acknowledgements": 2
        }
    }))
    .expect("profile publication config");
    let publication = config.profile_publication.expect("publication enabled");
    assert_eq!(
        publication.relays,
        [
            "wss://relay.omachat.example/",
            "wss://community.example/nostr",
            "ws://127.0.0.1:7447/"
        ]
    );
    assert_eq!(publication.required_acknowledgements, 2);
}

#[test]
fn unsafe_ambiguous_or_unsatisfiable_profile_policies_fail_closed() {
    let too_many_relays = (0..17)
        .map(|index| format!("wss://relay-{index}.example/"))
        .collect::<Vec<_>>();
    let cases = [
        json!({"relays": [], "required_acknowledgements": 1}),
        json!({"relays": ["wss://relay.example/"], "required_acknowledgements": 0}),
        json!({"relays": ["wss://relay.example/"], "required_acknowledgements": 2}),
        json!({"relays": too_many_relays, "required_acknowledgements": 1}),
        json!({
            "relays": ["wss://relay.example", "wss://relay.example/"],
            "required_acknowledgements": 1
        }),
        json!({"relays": ["ws://relay.example/"], "required_acknowledgements": 1}),
        json!({"relays": ["ws://localhost:7447/"], "required_acknowledgements": 1}),
        json!({"relays": ["wss://user@relay.example/"], "required_acknowledgements": 1}),
        json!({"relays": ["wss://relay.example/?token=secret"], "required_acknowledgements": 1}),
        json!({"relays": ["wss://relay.example/#workspace"], "required_acknowledgements": 1}),
        json!({
            "relays": ["wss://relay.example/"],
            "required_acknowledgements": 1,
            "authority": true
        }),
    ];
    for profile_publication in cases {
        assert!(
            load(json!({"profile_publication": profile_publication})).is_err(),
            "unsafe policy was accepted"
        );
    }
}
