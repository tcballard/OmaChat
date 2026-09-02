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
fn geochat_and_dm_relays_accept_wss_and_numeric_loopback() {
    let config = load(json!({
        "relays": [
            "wss://geochat.example/",
            "ws://127.0.0.1:7447/"
        ],
        "dm_relays": [
            "wss://inbox.example/",
            "ws://[::1]:7448/"
        ]
    }))
    .expect("secure and numeric-loopback relays should load");
    assert_eq!(
        config.relays,
        ["wss://geochat.example/", "ws://127.0.0.1:7447/"]
    );
    assert_eq!(
        config.dm_relays,
        ["wss://inbox.example/", "ws://[::1]:7448/"]
    );
}

#[test]
fn plaintext_or_ambiguous_geochat_and_dm_relays_fail_closed() {
    let cases = [
        json!({"relays": ["ws://relay.example/"]}),
        json!({"relays": ["ws://localhost:7447/"]}),
        json!({"relays": ["wss://user@relay.example/"]}),
        json!({"relays": ["wss://relay.example/?token=secret"]}),
        json!({"relays": ["wss://relay.example/#channel"]}),
        json!({"dm_relays": ["ws://relay.example/"]}),
        json!({"dm_relays": ["ws://localhost:7447/"]}),
        json!({"dm_relays": ["wss://user@relay.example/"]}),
        json!({"dm_relays": ["wss://relay.example/?token=secret"]}),
        json!({"dm_relays": ["wss://relay.example/#inbox"]}),
        json!({"dm_relays": ["https://not-a-websocket.example"]}),
    ];
    for value in cases {
        assert!(
            load(value.clone()).is_err(),
            "unsafe relay URL was accepted: {value}"
        );
    }
}
