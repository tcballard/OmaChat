use omachat_proto::ipc::{Command, Request, VERSION};
use serde_json::json;

#[test]
fn handle_commands_round_trip_and_chat_methods_are_gone() {
    let cases = [
        (
            Command::HostedClaimHandle {
                handle: "ada".into(),
            },
            json!({"version": VERSION, "id": "h", "method": "hosted-claim-handle", "params": {"handle": "ada"}}),
        ),
        (
            Command::HostedResolveHandle {
                handle: "ada".into(),
            },
            json!({"version": VERSION, "id": "h", "method": "hosted-resolve-handle", "params": {"handle": "ada"}}),
        ),
    ];
    for (command, wire) in cases {
        let request = Request {
            version: VERSION,
            id: "h".into(),
            command,
        };
        assert_eq!(serde_json::to_value(&request).unwrap(), wire);
        assert_eq!(serde_json::from_value::<Request>(wire).unwrap(), request);
    }
    for wire in [
        json!({"version": VERSION, "id": "x", "method": "send", "params": {"conversation": "c", "text": "hi"}}),
        json!({"version": VERSION, "id": "x", "method": "hosted-open-dm", "params": {"handle": "ada"}}),
        json!({"version": VERSION, "id": "x", "method": "hosted-create-workspace", "params": {"name": "team"}}),
        json!({"version": VERSION, "id": "x", "method": "save-draft", "params": {"conversation": "c", "text": "t", "expected_revision": 0}}),
        json!({"version": VERSION, "id": "x", "method": "hosted-claim-handle", "params": {}}),
        json!({"version": VERSION, "id": "x", "method": "hosted-claim-handle", "params": {"handle": "ada", "force": true}}),
    ] {
        assert!(
            serde_json::from_value::<Request>(wire.clone()).is_err(),
            "accepted retired or invalid command: {wire}"
        );
    }
}
