use omachat_proto::ipc::{Command, Request, VERSION};
use serde_json::json;

fn round_trip(command: Command, expected: serde_json::Value) {
    let request = Request {
        version: VERSION,
        id: "hosted-1".into(),
        command,
    };
    let encoded = serde_json::to_value(&request).unwrap();
    assert_eq!(encoded, expected);
    assert_eq!(serde_json::from_value::<Request>(encoded).unwrap(), request);
}

#[test]
fn hosted_requests_round_trip_through_the_strict_wire_contract() {
    round_trip(
        Command::HostedConversations,
        json!({"version": VERSION, "id": "hosted-1", "method": "hosted-conversations"}),
    );
    round_trip(
        Command::HostedHistory {
            conversation: "hosted:abc".into(),
            before_sequence: None,
            limit: None,
        },
        json!({
            "version": VERSION,
            "id": "hosted-1",
            "method": "hosted-history",
            "params": {"conversation": "hosted:abc"}
        }),
    );
    round_trip(
        Command::HostedHistory {
            conversation: "hosted:abc".into(),
            before_sequence: Some(40),
            limit: Some(20),
        },
        json!({
            "version": VERSION,
            "id": "hosted-1",
            "method": "hosted-history",
            "params": {"conversation": "hosted:abc", "before_sequence": 40, "limit": 20}
        }),
    );
    round_trip(
        Command::HostedMarkRead {
            conversation: "hosted:abc".into(),
            sequence: 7,
        },
        json!({
            "version": VERSION,
            "id": "hosted-1",
            "method": "hosted-mark-read",
            "params": {"conversation": "hosted:abc", "sequence": 7}
        }),
    );
    round_trip(
        Command::HostedOpenDm {
            handle: "bob".into(),
        },
        json!({
            "version": VERSION,
            "id": "hosted-1",
            "method": "hosted-open-dm",
            "params": {"handle": "bob"}
        }),
    );
    round_trip(
        Command::HostedClaimHandle {
            handle: "alice".into(),
        },
        json!({
            "version": VERSION,
            "id": "hosted-1",
            "method": "hosted-claim-handle",
            "params": {"handle": "alice"}
        }),
    );
    round_trip(
        Command::HostedResolveHandle {
            handle: "alice".into(),
        },
        json!({
            "version": VERSION,
            "id": "hosted-1",
            "method": "hosted-resolve-handle",
            "params": {"handle": "alice"}
        }),
    );
    round_trip(
        Command::HostedCreateWorkspace {
            name: "Acme".into(),
        },
        json!({
            "version": VERSION,
            "id": "hosted-1",
            "method": "hosted-create-workspace",
            "params": {"name": "Acme"}
        }),
    );
    round_trip(
        Command::HostedCreateChannel {
            workspace_id: "ws".into(),
            name: "general".into(),
        },
        json!({
            "version": VERSION,
            "id": "hosted-1",
            "method": "hosted-create-channel",
            "params": {"workspace_id": "ws", "name": "general"}
        }),
    );
    round_trip(
        Command::HostedAddMember {
            workspace_id: "ws".into(),
            handle: "bob".into(),
        },
        json!({
            "version": VERSION,
            "id": "hosted-1",
            "method": "hosted-add-member",
            "params": {"workspace_id": "ws", "handle": "bob"}
        }),
    );
}

#[test]
fn hosted_requests_reject_unknown_and_missing_fields() {
    for value in [
        json!({"version": VERSION, "id": "x", "method": "hosted-history", "params": {}}),
        json!({"version": VERSION, "id": "x", "method": "hosted-history", "params": {"conversation": "a", "after": 1}}),
        json!({"version": VERSION, "id": "x", "method": "hosted-mark-read", "params": {"conversation": "a"}}),
        json!({"version": VERSION, "id": "x", "method": "hosted-conversations", "params": {"all": true}}),
        json!({"version": VERSION, "id": "x", "method": "hosted-add-member", "params": {"workspace_id": "w"}}),
    ] {
        assert!(
            serde_json::from_value::<Request>(value.clone()).is_err(),
            "{value} must be rejected"
        );
    }
}
