use omachat_proto::ipc::{Command, Request};

#[test]
fn draft_commands_round_trip_and_refuse_unknown_fields() {
    for command in [
        Command::ListDrafts,
        Command::GetDraft {
            conversation: "#gcpvj".into(),
        },
        Command::SaveDraft {
            conversation: "#gcpvj".into(),
            text: "unfinished".into(),
            expected_revision: 3,
        },
    ] {
        let request = Request {
            version: 2,
            id: "draft-test".into(),
            command,
        };
        let bytes = serde_json::to_vec(&request).unwrap();
        let decoded: Request = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(serde_json::to_vec(&decoded).unwrap(), bytes);
    }
    for params in [
        r##"{"conversation":"#gcpvj","text":"draft","expected_revision":-1}"##,
        r##"{"conversation":"#gcpvj","text":"draft"}"##,
        r##"{"conversation":"#gcpvj","text":"draft","expected_revision":0,"force":true}"##,
    ] {
        let request =
            format!(r##"{{"version":3,"id":"draft","method":"save-draft","params":{params}}}"##);
        assert!(serde_json::from_str::<Request>(&request).is_err());
    }
}
