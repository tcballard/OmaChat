use omachat_proto::ipc::{Command, Request, VERSION};
use serde_json::json;

#[test]
fn cached_registry_handle_lookup_round_trips_through_the_strict_contract() {
    let request = Request {
        version: VERSION,
        id: "registry-cache-1".into(),
        command: Command::ShowRegistryHandle {
            handle: "alice".into(),
        },
    };
    let encoded = serde_json::to_value(&request).expect("serialize request");
    assert_eq!(
        encoded,
        json!({
            "version": VERSION,
            "id": "registry-cache-1",
            "method": "show-registry-handle",
            "params": { "handle": "alice" }
        })
    );
    assert_eq!(
        serde_json::from_value::<Request>(encoded).expect("deserialize request"),
        request
    );
}
