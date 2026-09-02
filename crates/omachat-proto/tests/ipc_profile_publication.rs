use omachat_proto::ipc::{Command, Request, VERSION};
use serde_json::json;

#[test]
fn profile_publication_round_trips_through_the_strict_wire_contract() {
    let request = Request {
        version: VERSION,
        id: "profile-publish-1".into(),
        command: Command::PublishProfile,
    };
    let encoded = serde_json::to_value(&request).expect("serialize request");
    assert_eq!(
        encoded,
        json!({
            "version": VERSION,
            "id": "profile-publish-1",
            "method": "publish-profile"
        })
    );
    assert_eq!(
        serde_json::from_value::<Request>(encoded)
            .expect("deserialize request")
            .command,
        Command::PublishProfile
    );
    assert!(
        serde_json::from_value::<Request>(json!({
            "version": VERSION,
            "id": "profile-publish-2",
            "method": "publish-profile",
            "params": {}
        }))
        .is_err()
    );
}
