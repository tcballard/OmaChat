use omachat_proto::ipc::{Command, Request, VERSION};
use serde_json::json;

#[test]
fn registry_handle_resolution_round_trips_through_the_strict_wire_contract() {
    let request = Request {
        version: VERSION,
        id: "registry-1".into(),
        command: Command::ResolveRegistryHandle {
            handle: "alice".into(),
        },
    };
    let encoded = serde_json::to_value(&request).expect("serialize request");
    assert_eq!(
        encoded,
        json!({
            "version": VERSION,
            "id": "registry-1",
            "method": "resolve-registry-handle",
            "params": { "handle": "alice" }
        })
    );
    assert_eq!(
        serde_json::from_value::<Request>(encoded).expect("deserialize request"),
        request
    );
    assert!(
        serde_json::from_value::<Request>(json!({
            "version": VERSION,
            "id": "registry-2",
            "method": "resolve-registry-handle",
            "params": {
                "handle": "alice",
                "trust_relay": true
            }
        }))
        .is_err()
    );
}
