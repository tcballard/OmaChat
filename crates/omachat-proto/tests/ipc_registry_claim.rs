use omachat_proto::ipc::{Command, Request, VERSION};
use serde_json::json;

#[test]
fn registry_handle_claim_round_trips_with_explicit_confirmation() {
    let request = Request {
        version: VERSION,
        id: "registry-claim-1".into(),
        command: Command::ClaimRegistryHandle {
            handle: "alice".into(),
            confirmation: "alice".into(),
        },
    };
    let encoded = serde_json::to_value(&request).expect("serialize request");
    assert_eq!(
        encoded,
        json!({
            "version": VERSION,
            "id": "registry-claim-1",
            "method": "claim-registry-handle",
            "params": {
                "handle": "alice",
                "confirmation": "alice"
            }
        })
    );
    assert_eq!(
        serde_json::from_value::<Request>(encoded).expect("deserialize request"),
        request
    );
    assert!(
        serde_json::from_value::<Request>(json!({
            "version": VERSION,
            "id": "registry-claim-2",
            "method": "claim-registry-handle",
            "params": { "handle": "alice" }
        }))
        .is_err()
    );
}
