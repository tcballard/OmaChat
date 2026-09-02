use omachat_proto::ipc::{Command, Request};

#[test]
fn discover_nip65_relays_has_a_strict_wire_contract() {
    let request = Request {
        version: 1,
        id: "nip65-discover-1".to_owned(),
        command: Command::DiscoverNip65Relays {
            public_key: "11".repeat(32),
        },
    };

    let value = serde_json::to_value(request).expect("request should serialize");
    assert_eq!(
        value,
        serde_json::json!({
            "version": 1,
            "id": "nip65-discover-1",
            "method": "discover-nip65-relays",
            "params": { "public_key": "11".repeat(32) }
        })
    );

    let mut with_unknown = value;
    with_unknown["params"]["trusted"] = serde_json::json!(true);
    assert!(serde_json::from_value::<Request>(with_unknown).is_err());
}

#[test]
fn show_nip65_relays_has_a_strict_wire_contract() {
    let request = Request {
        version: 1,
        id: "nip65-show-1".to_owned(),
        command: Command::ShowNip65Relays {
            public_key: "22".repeat(32),
        },
    };

    let value = serde_json::to_value(request).expect("request should serialize");
    assert_eq!(
        value,
        serde_json::json!({
            "version": 1,
            "id": "nip65-show-1",
            "method": "show-nip65-relays",
            "params": { "public_key": "22".repeat(32) }
        })
    );

    let mut with_unknown = value;
    with_unknown["params"]["relay"] = serde_json::json!("wss://relay.example");
    assert!(serde_json::from_value::<Request>(with_unknown).is_err());
}
