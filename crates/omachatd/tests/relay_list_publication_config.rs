use std::fs;

use omachatd::{DaemonConfig, RelayListPublicationRelayConfig};
use tempfile::tempdir;

#[test]
fn relay_list_publication_is_disabled_unless_explicitly_configured() {
    let config = load(r#"{}"#).expect("default config should load");
    assert!(config.relay_list_publication.is_none());
}

#[test]
fn explicit_relay_roles_and_satisfiable_quorum_are_accepted() {
    let config = load(
        r#"{
            "relay_list_publication": {
                "relays": [
                    {"url":"wss://write.example", "read":false, "write":true},
                    {"url":"wss://both.example", "read":true, "write":true},
                    {"url":"wss://read.example", "read":true, "write":false}
                ],
                "required_acknowledgements": 2
            }
        }"#,
    )
    .expect("explicit NIP-65 policy should load");
    let publication = config
        .relay_list_publication
        .expect("publication should be configured");
    assert_eq!(publication.required_acknowledgements, 2);
    assert_eq!(
        publication.relays,
        vec![
            RelayListPublicationRelayConfig {
                url: "wss://write.example".into(),
                read: false,
                write: true,
            },
            RelayListPublicationRelayConfig {
                url: "wss://both.example".into(),
                read: true,
                write: true,
            },
            RelayListPublicationRelayConfig {
                url: "wss://read.example".into(),
                read: true,
                write: false,
            },
        ]
    );
    assert_eq!(
        publication
            .canonical_relays()
            .expect("validated relays should canonicalize"),
        vec![
            RelayListPublicationRelayConfig {
                url: "wss://both.example/".into(),
                read: true,
                write: true,
            },
            RelayListPublicationRelayConfig {
                url: "wss://read.example/".into(),
                read: true,
                write: false,
            },
            RelayListPublicationRelayConfig {
                url: "wss://write.example/".into(),
                read: false,
                write: true,
            },
        ]
    );
}

#[test]
fn unsafe_ambiguous_or_unsatisfiable_policies_fail_closed() {
    for invalid in [
        r#"{"relay_list_publication":{"relays":[],"required_acknowledgements":1}}"#,
        r#"{"relay_list_publication":{"relays":[{"url":"wss://none.example","read":false,"write":false}],"required_acknowledgements":1}}"#,
        r#"{"relay_list_publication":{"relays":[{"url":"wss://read.example","read":true,"write":false}],"required_acknowledgements":1}}"#,
        r#"{"relay_list_publication":{"relays":[{"url":"wss://one.example","read":true,"write":true}],"required_acknowledgements":0}}"#,
        r#"{"relay_list_publication":{"relays":[{"url":"wss://one.example","read":true,"write":true}],"required_acknowledgements":2}}"#,
        r#"{"relay_list_publication":{"relays":[{"url":"ws://relay.example","read":true,"write":true}],"required_acknowledgements":1}}"#,
        r#"{"relay_list_publication":{"relays":[{"url":"wss://user@relay.example","read":true,"write":true}],"required_acknowledgements":1}}"#,
        r#"{"relay_list_publication":{"relays":[{"url":"wss://relay.example?token=secret","read":true,"write":true}],"required_acknowledgements":1}}"#,
        r#"{"relay_list_publication":{"relays":[{"url":"wss://relay.example","read":true,"write":true},{"url":"wss://relay.example/","read":true,"write":true}],"required_acknowledgements":1}}"#,
        r#"{"relay_list_publication":{"relays":[{"url":"wss://relay.example","read":true,"write":true,"trusted":true}],"required_acknowledgements":1}}"#,
    ] {
        assert!(load(invalid).is_err(), "unsafe policy loaded: {invalid}");
    }
}

fn load(json: &str) -> Result<DaemonConfig, omachatd::CoreError> {
    let state = tempdir().unwrap();
    let path = state.path().join("config.json");
    fs::write(&path, json).unwrap();
    DaemonConfig::load(path)
}
