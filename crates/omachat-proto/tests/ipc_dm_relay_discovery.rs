use omachat_proto::ipc::{Command, Request, VERSION};
use serde_json::json;

#[test]
fn discovery_request_round_trips_through_the_strict_wire_contract() {
    let request = Request {
        version: VERSION,
        id: "discover-1".into(),
        command: Command::DiscoverDmRelays {
            public_key: "11".repeat(32),
        },
    };
    let encoded = serde_json::to_value(&request).unwrap();
    assert_eq!(
        encoded,
        json!({
            "version": VERSION,
            "id": "discover-1",
            "method": "discover-dm-relays",
            "params": { "public_key": "11".repeat(32) }
        })
    );
    assert_eq!(serde_json::from_value::<Request>(encoded).unwrap(), request);

    assert!(
        serde_json::from_value::<Request>(json!({
            "version": VERSION,
            "id": "discover-2",
            "method": "discover-dm-relays",
            "params": {
                "public_key": "11".repeat(32),
                "trusted": true
            }
        }))
        .is_err()
    );
}
