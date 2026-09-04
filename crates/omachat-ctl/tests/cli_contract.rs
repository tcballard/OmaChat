//! Black-box scripting contract against a deterministic local IPC peer.
use omachat_proto::ipc::{
    Command, ErrorBody, ErrorCode, MAX_LINE_BYTES, Request, Response, ResponseOutcome, VERSION,
    encode_line,
};
use serde_json::{Value, json};
use std::{
    future::Future,
    path::Path,
    process::{Child, Command as Process, Output, Stdio},
    thread,
    time::{Duration, Instant},
};
use tempfile::tempdir;
use tokio::{
    io::{AsyncBufReadExt, AsyncWriteExt, BufReader},
    net::{UnixListener, UnixStream},
    time::timeout,
};

const TEST_DEADLINE: Duration = Duration::from_secs(12);
type Peer = BufReader<UnixStream>;

struct ChildGuard(Option<Child>);
impl Drop for ChildGuard {
    fn drop(&mut self) {
        if let Some(child) = self.0.as_mut() {
            let _ = child.kill();
            let _ = child.wait();
        }
    }
}

fn run(socket: &Path, args: &[String]) -> Output {
    let mut child = ChildGuard(Some(
        Process::new(env!("CARGO_BIN_EXE_omachat-ctl"))
            .arg("--socket")
            .arg(socket)
            .args(args)
            .env("TOKIO_WORKER_THREADS", "2")
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap(),
    ));
    let start = Instant::now();
    while child.0.as_mut().unwrap().try_wait().unwrap().is_none() {
        assert!(
            start.elapsed() < TEST_DEADLINE,
            "CLI exceeded its timeout contract"
        );
        thread::sleep(Duration::from_millis(20));
    }
    child.0.take().unwrap().wait_with_output().unwrap()
}

async fn with_peer<F, Fut>(args: &[&str], serve: F) -> Output
where
    F: FnOnce(Peer) -> Fut + Send + 'static,
    Fut: Future<Output = ()> + Send + 'static,
{
    let dir = tempdir().unwrap();
    let socket = dir.path().join("ipc.sock");
    let listener = UnixListener::bind(&socket).unwrap();
    let server = tokio::spawn(async move {
        timeout(TEST_DEADLINE, async {
            let (stream, _) = listener.accept().await.unwrap();
            serve(BufReader::new(stream)).await;
        })
        .await
        .expect("stub peer deadline");
    });
    let args = args.iter().map(|arg| (*arg).to_owned()).collect::<Vec<_>>();
    let output = tokio::task::spawn_blocking(move || run(&socket, &args))
        .await
        .unwrap();
    server.await.unwrap();
    output
}

async fn request(peer: &mut Peer) -> Request {
    let mut line = String::new();
    assert!(peer.read_line(&mut line).await.unwrap() > 0);
    serde_json::from_str(&line).unwrap()
}

async fn respond(peer: &mut Peer, request: &Request, outcome: ResponseOutcome) {
    peer.get_mut()
        .write_all(
            &encode_line(&Response {
                version: VERSION,
                id: request.id.clone(),
                outcome,
            })
            .unwrap(),
        )
        .await
        .unwrap();
}

async fn hello(peer: &mut Peer) {
    let request = request(peer).await;
    assert_eq!(request.version, VERSION);
    assert_eq!(
        request.command,
        Command::Hello {
            minimum_version: VERSION,
            maximum_version: VERSION
        }
    );
    respond(
        peer,
        &request,
        ResponseOutcome::Ok {
            result: json!({"version": VERSION}),
        },
    )
    .await;
}

fn assert_failure(output: &Output, code: i32, message: &str) {
    assert_eq!(output.status.code(), Some(code));
    assert!(
        output.stdout.is_empty(),
        "failure must not emit successful JSON"
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains(message), "unexpected stderr: {stderr}");
    assert!(
        !output.stderr.contains(&0x1b),
        "redirected stderr contains ANSI escapes"
    );
}

#[test]
fn missing_daemon_and_invalid_arguments_have_distinct_exit_codes() {
    let dir = tempdir().unwrap();
    let socket = dir.path().join("absent.sock");
    assert_failure(
        &run(&socket, &["status".into(), "--json".into()]),
        3,
        "daemon connection failed",
    );
    for args in [
        vec![],
        vec!["unknown".into()],
        vec!["send".into(), "missing-text".into()],
    ] {
        assert_failure(&run(&socket, &args), 2, "usage: omachat-ctl");
    }
}

#[tokio::test]
async fn status_json_is_stable_single_line_and_has_no_redirected_color() {
    let mut outputs = Vec::new();
    for _ in 0..2 {
        outputs.push(with_peer(&["status", "--json"], |mut peer| async move {
            hello(&mut peer).await;
            let request = request(&mut peer).await;
            assert_eq!(request.command, Command::Status);
            respond(&mut peer, &request, ResponseOutcome::Ok {
                result: json!({"storage_provider":"file", "outbox_pending":2, "joined_geohashes":["gcpvj"]}),
            }).await;
        }).await);
    }
    for output in &outputs {
        assert!(output.status.success());
        assert!(output.stderr.is_empty());
        assert_eq!(output.stdout, b"{\"joined_geohashes\":[\"gcpvj\"],\"outbox_pending\":2,\"storage_provider\":\"file\"}\n");
        assert!(!output.stdout.contains(&0x1b));
        assert!(serde_json::from_slice::<Value>(&output.stdout).is_ok());
    }
    assert_eq!(outputs[0].stdout, outputs[1].stdout);
}

#[tokio::test]
async fn core_commands_negotiate_then_preserve_arguments_and_correlation() {
    for (args, expected) in [
        (vec!["fingerprint"], Command::Fingerprint),
        (
            vec!["join", "gcpvj"],
            Command::Join {
                geohash: "gcpvj".into(),
            },
        ),
        (
            vec!["leave", "gcpvj"],
            Command::Leave {
                geohash: "gcpvj".into(),
            },
        ),
        (
            vec!["send", "gcpvj", "hello\nworld 🦀"],
            Command::Send {
                conversation: "gcpvj".into(),
                text: "hello\nworld 🦀".into(),
            },
        ),
    ] {
        let output = with_peer(&args, |mut peer| async move {
            hello(&mut peer).await;
            let request = request(&mut peer).await;
            assert_eq!(request.version, VERSION);
            assert_eq!(request.command, expected);
            respond(
                &mut peer,
                &request,
                ResponseOutcome::Ok {
                    result: json!("accepted"),
                },
            )
            .await;
        })
        .await;
        assert!(output.status.success());
        assert_eq!(output.stdout, b"accepted\n");
        assert!(output.stderr.is_empty());
    }
}

#[tokio::test]
async fn incompatible_response_versions_fail_at_hello_and_after_hello() {
    for after_hello in [false, true] {
        let output = with_peer(&["status", "--json"], move |mut peer| async move {
            if after_hello {
                hello(&mut peer).await;
            }
            let request = request(&mut peer).await;
            peer.get_mut()
                .write_all(
                    &encode_line(&Response {
                        version: VERSION + 1,
                        id: request.id,
                        outcome: ResponseOutcome::Ok { result: json!({}) },
                    })
                    .unwrap(),
                )
                .await
                .unwrap();
        })
        .await;
        assert_failure(&output, 4, "incompatible IPC version");
    }
}

#[tokio::test]
async fn remote_errors_have_exit_four_and_no_success_output() {
    for after_hello in [false, true] {
        let output = with_peer(&["status", "--json"], move |mut peer| async move {
            if after_hello {
                hello(&mut peer).await;
            }
            let request = request(&mut peer).await;
            respond(
                &mut peer,
                &request,
                ResponseOutcome::Error {
                    error: ErrorBody {
                        code: ErrorCode::VersionMismatch,
                        message: "test rejection".into(),
                    },
                },
            )
            .await;
        })
        .await;
        assert_failure(&output, 4, "test rejection");
    }
}

#[tokio::test]
async fn silent_peer_times_out_at_hello_and_after_hello() {
    for after_hello in [false, true] {
        let output = with_peer(&["status", "--json"], move |mut peer| async move {
            if after_hello {
                hello(&mut peer).await;
            }
            request(&mut peer).await;
            // Keep the connection open without a response until the CLI's
            // actual five-second timeout closes it. No test-only timeout knob.
            assert_eq!(peer.read_line(&mut String::new()).await.unwrap(), 0);
        })
        .await;
        assert_failure(&output, 5, "daemon request timed out");
    }
}

#[tokio::test]
async fn malformed_oversized_uncorrelated_and_disconnected_replies_fail_closed() {
    for (bytes, message) in [
        (b"not JSON\n".to_vec(), "response is malformed"),
        (
            vec![b'x'; MAX_LINE_BYTES + 1],
            "response exceeds the size limit",
        ),
        (
            encode_line(&Response {
                version: VERSION,
                id: "wrong-id".into(),
                outcome: ResponseOutcome::Ok { result: json!({}) },
            })
            .unwrap(),
            "response ID does not match",
        ),
        (Vec::new(), "daemon disconnected"),
    ] {
        let output = with_peer(&["status", "--json"], move |mut peer| async move {
            hello(&mut peer).await;
            request(&mut peer).await;
            peer.get_mut().write_all(&bytes).await.unwrap();
        })
        .await;
        assert_failure(&output, 3, message);
    }
}
