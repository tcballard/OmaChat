//! Two-phase destructive-command orchestration against a scripted stub daemon.

use omachat_ctl::{Client, ClientError, DEFAULT_TIMEOUT, request_with_confirmation};
use omachat_proto::ipc::{
    Command, RequestDecoder, Response, ResponseOutcome, VERSION, encode_line, negotiate,
};
use serde_json::json;
use std::path::Path;
use tempfile::tempdir;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::UnixListener,
};

/// Serves one client: hello, then request-panic-confirmation (mints a token
/// file), then panic (accepted only with the minted token).
async fn stub_daemon(listener: UnixListener, token_directory: std::path::PathBuf) {
    let (mut stream, _) = listener.accept().await.expect("accept");
    let mut decoder = RequestDecoder::default();
    let mut buffer = [0_u8; 4096];
    let mut minted: Option<String> = None;
    loop {
        let count = match stream.read(&mut buffer).await {
            Ok(0) | Err(_) => return,
            Ok(count) => count,
        };
        for request in decoder.push(&buffer[..count]).expect("decode request") {
            let outcome = match &request.command {
                Command::Hello {
                    minimum_version,
                    maximum_version,
                } => ResponseOutcome::Ok {
                    result: serde_json::to_value(
                        negotiate(*minimum_version, *maximum_version).expect("negotiate"),
                    )
                    .expect("hello result"),
                },
                Command::RequestPanicConfirmation => {
                    let token = "a".repeat(64);
                    let token_path = token_directory.join("panic.token");
                    std::fs::write(&token_path, &token).expect("write token file");
                    minted = Some(token);
                    ResponseOutcome::Ok {
                        result: json!({
                            "token_path": token_path.display().to_string(),
                            "expires_at": 1_u64,
                            "ttl_seconds": 120_u64,
                        }),
                    }
                }
                Command::Panic { confirmation } => {
                    assert_eq!(
                        Some(confirmation.as_str()),
                        minted.as_deref(),
                        "client must echo the minted token, not the typed intent"
                    );
                    ResponseOutcome::Ok {
                        result: json!({"panic": "erased"}),
                    }
                }
                command => panic!("unexpected command: {command:?}"),
            };
            let response = Response {
                version: VERSION,
                id: request.id,
                outcome,
            };
            stream
                .write_all(&encode_line(&response).expect("encode response"))
                .await
                .expect("write response");
        }
    }
}

async fn connect(socket: &Path) -> Client {
    Client::connect(socket, DEFAULT_TIMEOUT)
        .await
        .expect("connect client")
}

#[tokio::test]
async fn panic_orchestrates_token_request_and_commit() {
    let temporary = tempdir().expect("temporary directory");
    let socket = temporary.path().join("stub.sock");
    let listener = UnixListener::bind(&socket).expect("bind stub");
    let server = tokio::spawn(stub_daemon(listener, temporary.path().to_owned()));
    let mut client = connect(&socket).await;
    let response = request_with_confirmation(
        &mut client,
        Command::Panic {
            confirmation: "ERASE".into(),
        },
    )
    .await
    .expect("two-phase panic");
    assert!(matches!(response.outcome, ResponseOutcome::Ok { .. }));
    drop(client);
    server.await.expect("stub daemon");
}

#[tokio::test]
async fn mistyped_intent_is_refused_before_any_daemon_interaction() {
    let temporary = tempdir().expect("temporary directory");
    let socket = temporary.path().join("stub.sock");
    let listener = UnixListener::bind(&socket).expect("bind stub");
    let server = tokio::spawn(stub_daemon(listener, temporary.path().to_owned()));
    let mut client = connect(&socket).await;
    let error = request_with_confirmation(
        &mut client,
        Command::Panic {
            confirmation: "erase".into(),
        },
    )
    .await
    .expect_err("typed intent must be exact");
    assert!(matches!(error, ClientError::ConfirmationRefused(_)));
    drop(client);
    server.await.expect("stub daemon");
}
