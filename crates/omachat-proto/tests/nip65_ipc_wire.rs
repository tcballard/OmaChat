use omachat_proto::ipc::{Command, IpcError, RequestDecoder, VERSION, encode_line};

fn decode(line: &str) -> Command {
    let mut decoder = RequestDecoder::default();
    let requests = decoder
        .push(format!("{line}\n").as_bytes())
        .expect("valid strict request");
    assert_eq!(requests.len(), 1);
    requests.into_iter().next().expect("one request").command
}

#[test]
fn nip65_publication_is_a_strict_parameterless_command() {
    let command = decode(r#"{"version":2,"id":"publish","method":"publish-nip65-relays"}"#);
    assert_eq!(command, Command::PublishNip65Relays);

    let encoded = encode_line(&omachat_proto::ipc::Request {
        version: VERSION,
        id: "publish".into(),
        command,
    })
    .expect("encode request");
    assert_eq!(
        std::str::from_utf8(&encoded).expect("UTF-8 request"),
        "{\"version\":2,\"id\":\"publish\",\"method\":\"publish-nip65-relays\"}\n"
    );

    let mut decoder = RequestDecoder::default();
    assert_eq!(
        decoder.push(
            b"{\"version\":2,\"id\":\"publish\",\"method\":\"publish-nip65-relays\",\"params\":{}}\n"
        ),
        Err(IpcError::MalformedJson)
    );
}
