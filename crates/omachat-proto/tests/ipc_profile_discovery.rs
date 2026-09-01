use omachat_proto::ipc::{Command, Request, VERSION};
use serde_json::json;

#[test]
fn profile_discovery_round_trips_through_the_strict_wire_contract() {
    let request = Request {
        version: VERSION,
        id: "profile-1".into(),
        command: Command::DiscoverProfile {
            public_key: "22".repeat(32),
        },
    };
    let encoded = serde_json::to_value(&request).unwrap();
    assert_eq!(
        encoded,
        json!({
            "version": VERSION,
            "id": "profile-1",
            "method": "discover-profile",
            "params": { "public_key": "22".repeat(32) }
        })
    );
    assert_eq!(serde_json::from_value::<Request>(encoded).unwrap(), request);
    assert!(
        serde_json::from_value::<Request>(json!({
            "version": VERSION,
            "id": "profile-2",
            "method": "discover-profile",
            "params": {
                "public_key": "22".repeat(32),
                "global_handle_verified": true
            }
        }))
        .is_err()
    );
}
