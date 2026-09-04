use omachat_proto::ipc::{
    Command, ErrorBody, ErrorCode, IpcError, MAX_LINE_BYTES, Request, RequestDecoder, Response,
    ResponseOutcome, Topic, VERSION, encode_line, negotiate,
};
use serde_json::Value;

#[test]
fn fragmented_and_coalesced_requests_keep_correlation_ids() {
    let first = Request {
        version: VERSION,
        id: "a".into(),
        command: Command::Status,
    };
    let second = Request {
        version: VERSION,
        id: "b".into(),
        command: Command::Fingerprint,
    };
    let mut wire = encode_line(&first).expect("first");
    wire.extend(encode_line(&second).expect("second"));
    let split = wire.len() / 3;
    let mut decoder = RequestDecoder::default();
    assert!(decoder.push(&wire[..split]).expect("fragment").is_empty());
    assert_eq!(
        decoder.push(&wire[split..]).expect("remainder"),
        vec![first, second]
    );
    decoder.finish().expect("complete stream");
}

#[test]
fn oversized_malformed_and_unknown_fields_fail_boundedly() {
    let mut decoder = RequestDecoder::default();
    assert_eq!(
        decoder.push(&vec![b'x'; MAX_LINE_BYTES + 1]),
        Err(IpcError::LineTooLarge {
            maximum: MAX_LINE_BYTES
        })
    );
    assert_eq!(decoder.push(b"not-json\n"), Err(IpcError::MalformedJson));
    assert_eq!(
        decoder.push(b"{\"version\":1,\"id\":\"x\",\"method\":\"status\",\"extra\":true}\n"),
        Err(IpcError::MalformedJson)
    );
}

#[test]
fn hello_negotiation_is_explicit() {
    assert_eq!(negotiate(1, 1).expect("compatible").version, VERSION);
    assert!(matches!(
        negotiate(2, 3),
        Err(IpcError::VersionMismatch { supported: 1, .. })
    ));
}

#[test]
fn requests_preserve_the_flat_wire_format() {
    let cases = [
        (
            Command::Hello {
                minimum_version: 1,
                maximum_version: 2,
            },
            r#"{"version":1,"id":"request","method":"hello","params":{"minimum_version":1,"maximum_version":2}}"#,
        ),
        (
            Command::Status,
            r#"{"version":1,"id":"request","method":"status"}"#,
        ),
        (
            Command::Fingerprint,
            r#"{"version":1,"id":"request","method":"fingerprint"}"#,
        ),
        (
            Command::Join {
                geohash: "u4pruy".into(),
            },
            r#"{"version":1,"id":"request","method":"join","params":{"geohash":"u4pruy"}}"#,
        ),
        (
            Command::Leave {
                geohash: "u4pruy".into(),
            },
            r#"{"version":1,"id":"request","method":"leave","params":{"geohash":"u4pruy"}}"#,
        ),
        (
            Command::Send {
                conversation: "general".into(),
                text: "hello".into(),
            },
            r#"{"version":1,"id":"request","method":"send","params":{"conversation":"general","text":"hello"}}"#,
        ),
        (
            Command::Who {
                geohash: "u4pruy".into(),
            },
            r#"{"version":1,"id":"request","method":"who","params":{"geohash":"u4pruy"}}"#,
        ),
        (
            Command::Block {
                public_key: "pubkey".into(),
            },
            r#"{"version":1,"id":"request","method":"block","params":{"public_key":"pubkey"}}"#,
        ),
        (
            Command::JoinRoom {
                relay: "wss://rooms.example".into(),
                group_id: "omarchy".into(),
                invite_code: None,
            },
            r#"{"version":1,"id":"request","method":"join-room","params":{"relay":"wss://rooms.example","group_id":"omarchy"}}"#,
        ),
        (
            Command::JoinRoom {
                relay: "wss://rooms.example".into(),
                group_id: "omarchy".into(),
                invite_code: Some("welcome".into()),
            },
            r#"{"version":1,"id":"request","method":"join-room","params":{"relay":"wss://rooms.example","group_id":"omarchy","invite_code":"welcome"}}"#,
        ),
        (
            Command::LeaveRoom {
                relay: "wss://rooms.example".into(),
                group_id: "omarchy".into(),
            },
            r#"{"version":1,"id":"request","method":"leave-room","params":{"relay":"wss://rooms.example","group_id":"omarchy"}}"#,
        ),
        (
            Command::ListRooms,
            r#"{"version":1,"id":"request","method":"list-rooms"}"#,
        ),
        (
            Command::RoomMembers {
                relay: "wss://rooms.example".into(),
                group_id: "omarchy".into(),
            },
            r#"{"version":1,"id":"request","method":"room-members","params":{"relay":"wss://rooms.example","group_id":"omarchy"}}"#,
        ),
        (
            Command::Panic {
                confirmation: "confirm".into(),
            },
            r#"{"version":1,"id":"request","method":"panic","params":{"confirmation":"confirm"}}"#,
        ),
        (
            Command::Subscribe {
                topics: vec![Topic::Status, Topic::Messages],
            },
            r#"{"version":1,"id":"request","method":"subscribe","params":{"topics":["status","messages"]}}"#,
        ),
    ];

    for (command, expected) in cases {
        let request = Request {
            version: VERSION,
            id: "request".into(),
            command,
        };
        let encoded = serde_json::to_string(&request).expect("request serializes");
        assert_eq!(encoded, expected);
        assert_eq!(
            serde_json::from_str::<Request>(&encoded).expect("request deserializes"),
            request
        );
    }
}

#[test]
fn request_fields_may_arrive_in_any_order() {
    let request = serde_json::from_str::<Request>(
        r#"{"params":{"text":"hello","conversation":"general"},"method":"send","id":"request","version":1}"#,
    )
    .expect("reordered request deserializes");
    assert_eq!(
        request,
        Request {
            version: VERSION,
            id: "request".into(),
            command: Command::Send {
                conversation: "general".into(),
                text: "hello".into(),
            },
        }
    );
}

#[test]
fn requests_reject_noncanonical_arms_and_fields() {
    let invalid = [
        r#"{"version":1,"id":"x","method":"send"}"#,
        r#"{"version":1,"id":"x","method":"send","params":null}"#,
        r#"{"version":1,"id":"x","method":"status","params":null}"#,
        r#"{"version":1,"id":"x","method":"status","params":{"conversation":"general","text":"hello"}}"#,
        r#"{"version":1,"id":"x","method":"send","params":{"conversation":"general","text":"hello","extra":true}}"#,
        r#"{"version":1,"id":"x","method":"send","params":{"conversation":"general","conversation":"other","text":"hello"}}"#,
        r#"{"version":1,"id":"x","method":"status","extra":true}"#,
        r#"{"version":1,"id":"x","method":"status","method":"status"}"#,
        r#"{"version":1,"id":"x","method":"unknown"}"#,
    ];

    for wire in invalid {
        assert!(
            serde_json::from_str::<Request>(wire).is_err(),
            "accepted invalid request: {wire}"
        );
    }
}

#[test]
fn responses_preserve_the_flat_wire_format_and_null_result() {
    let response = Response {
        version: VERSION,
        id: "response-1".into(),
        outcome: ResponseOutcome::Ok {
            result: Value::Null,
        },
    };
    let encoded = serde_json::to_string(&response).expect("response serializes");
    assert_eq!(
        encoded,
        r#"{"version":1,"id":"response-1","status":"ok","result":null}"#
    );
    assert_eq!(
        serde_json::from_str::<Response>(&encoded).expect("null result deserializes"),
        response
    );

    let error = Response {
        version: VERSION,
        id: "response-2".into(),
        outcome: ResponseOutcome::Error {
            error: ErrorBody {
                code: ErrorCode::Unavailable,
                message: "offline".into(),
            },
        },
    };
    assert_eq!(
        serde_json::to_string(&error).expect("error serializes"),
        r#"{"version":1,"id":"response-2","status":"error","error":{"code":"unavailable","message":"offline"}}"#
    );
    assert_eq!(
        serde_json::from_str::<Response>(
            r#"{"error":{"message":"offline","code":"unavailable"},"status":"error","id":"response-2","version":1}"#
        )
        .expect("reordered response deserializes"),
        error
    );
}

#[test]
fn responses_reject_missing_wrong_unknown_and_duplicate_arms() {
    let invalid = [
        r#"{"version":1,"id":"x","status":"ok"}"#,
        r#"{"version":1,"id":"x","status":"ok","error":{"code":"internal","message":"failed"}}"#,
        r#"{"version":1,"id":"x","status":"ok","result":null,"error":{"code":"internal","message":"failed"}}"#,
        r#"{"version":1,"id":"x","status":"error","result":null}"#,
        r#"{"version":1,"id":"x","status":"error","error":{"code":"internal","message":"failed"},"result":null}"#,
        r#"{"version":1,"id":"x","status":"error"}"#,
        r#"{"version":1,"id":"x","status":"error","error":null}"#,
        r#"{"version":1,"id":"x","status":"error","error":{"code":"internal","message":"failed","extra":true}}"#,
        r#"{"version":1,"id":"x","status":"ok","result":null,"extra":true}"#,
        r#"{"version":1,"id":"x","status":"ok","result":null,"result":null}"#,
        r#"{"version":1,"id":"x","status":"ok","status":"ok","result":null}"#,
        r#"{"version":1,"id":"x","status":"unknown","result":null}"#,
    ];

    for wire in invalid {
        assert!(
            serde_json::from_str::<Response>(wire).is_err(),
            "accepted invalid response: {wire}"
        );
    }
}
