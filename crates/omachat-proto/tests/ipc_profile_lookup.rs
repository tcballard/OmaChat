use omachat_proto::ipc::{Command, Request, VERSION};
use serde_json::json;

#[test]
fn profile_lookup_round_trips_through_the_strict_wire_contract() {
    let request = Request {
        version: VERSION,
        id: "profile-cache-1".into(),
        command: Command::ShowProfile {
            public_key: "33".repeat(32),
        },
    };
    let encoded = serde_json::to_value(&request).unwrap();
    assert_eq!(
        encoded,
        json!({
            "version": VERSION,
            "id": "profile-cache-1",
            "method": "show-profile",
            "params": { "public_key": "33".repeat(32) }
        })
    );
    assert_eq!(serde_json::from_value::<Request>(encoded).unwrap(), request);
}
