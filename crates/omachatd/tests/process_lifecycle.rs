//! Exercise the installed daemon entry point, not just DaemonCore methods.
use omachat_proto::ipc::{Command, Request, Response, ResponseOutcome, VERSION, encode_line};
use serde_json::{Value, json};
use std::{
    fs,
    io::{BufRead, BufReader, Write},
    os::unix::net::UnixStream,
    path::{Path, PathBuf},
    process::{Child, Command as Process, Stdio},
    thread,
    time::{Duration, Instant},
};
use tempfile::{TempDir, tempdir};

const DEADLINE: Duration = Duration::from_secs(10);

struct Fixture {
    dir: TempDir,
    config: PathBuf,
    socket: PathBuf,
}

impl Fixture {
    fn new() -> Self {
        let dir = tempdir().unwrap();
        let config = dir.path().join("config.json");
        let socket = dir.path().join("runtime/omachat.sock");
        let fixture = Self {
            dir,
            config,
            socket,
        };
        fixture.configure(json!({"storage_provider":"file", "joined_geohashes":["gcpvj"]}));
        fixture
    }

    fn configure(&self, config: Value) {
        fs::write(&self.config, serde_json::to_vec(&config).unwrap()).unwrap();
    }

    fn start(&self) -> Daemon {
        self.start_with_config(true)
    }

    fn start_with_config(&self, with_config: bool) -> Daemon {
        let log = self.dir.path().join("stderr.log");
        let mut command = Process::new(env!("CARGO_BIN_EXE_omachatd"));
        if with_config {
            command.arg("--config").arg(&self.config);
        }
        let child = command
            .arg("--file-key")
            .arg("--state")
            .arg(self.dir.path().join("state"))
            .arg("--socket")
            .arg(&self.socket)
            .env("XDG_RUNTIME_DIR", self.dir.path())
            .env("XDG_STATE_HOME", self.dir.path())
            .env("TOKIO_WORKER_THREADS", "2")
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(fs::File::create(&log).unwrap())
            .spawn()
            .unwrap();
        let mut daemon = Daemon { child, log };
        let start = Instant::now();
        loop {
            assert!(
                daemon.child.try_wait().unwrap().is_none(),
                "daemon exited: {}",
                daemon.log()
            );
            if let Ok(stream) = UnixStream::connect(&self.socket) {
                // The socket exists only after startup. Complete hello/status
                // as the readiness barrier before sending a process signal.
                let mut client = Client::new(stream);
                client.request(Command::Status);
                return daemon;
            }
            assert!(
                start.elapsed() < DEADLINE,
                "startup timed out: {}",
                daemon.log()
            );
            thread::sleep(Duration::from_millis(20));
        }
    }

    fn client(&self) -> Client {
        Client::new(UnixStream::connect(&self.socket).unwrap())
    }
}

struct Daemon {
    child: Child,
    log: PathBuf,
}

impl Daemon {
    fn log(&self) -> String {
        fs::read_to_string(&self.log).unwrap()
    }

    fn signal(&mut self, signal: &str) {
        assert!(
            self.child.try_wait().unwrap().is_none(),
            "daemon already exited: {}",
            self.log()
        );
        // This Child remains unreaped throughout signal delivery, so its PID
        // cannot be reused for an unrelated process.
        assert!(
            Process::new("kill")
                .arg(format!("-{signal}"))
                .arg(self.child.id().to_string())
                .status()
                .unwrap()
                .success()
        );
    }

    fn stop(&mut self, signal: &str, socket: &Path) {
        self.signal(signal);
        let start = Instant::now();
        loop {
            if let Some(status) = self.child.try_wait().unwrap() {
                assert!(
                    status.success(),
                    "unclean {signal} exit: {status}; {}",
                    self.log()
                );
                assert!(!socket.exists(), "shutdown left an IPC socket");
                assert!(
                    !socket.with_extension("lock").exists(),
                    "shutdown left an instance lock path"
                );
                return;
            }
            assert!(
                start.elapsed() < DEADLINE,
                "shutdown timed out: {}",
                self.log()
            );
            thread::sleep(Duration::from_millis(20));
        }
    }

    fn wait_for_rejected_reload(&self, previous: usize) {
        let start = Instant::now();
        while self.log().matches("rejected SIGHUP reload").count() <= previous {
            assert!(
                start.elapsed() < DEADLINE,
                "reload not observed: {}",
                self.log()
            );
            thread::sleep(Duration::from_millis(20));
        }
    }
}

impl Drop for Daemon {
    fn drop(&mut self) {
        // Reap on assertion failures too; never leave a background daemon.
        if matches!(self.child.try_wait(), Ok(None)) {
            let _ = self.child.kill();
        }
        let _ = self.child.wait();
    }
}

struct Client {
    reader: BufReader<UnixStream>,
    next_id: u64,
}

impl Client {
    fn new(stream: UnixStream) -> Self {
        stream.set_read_timeout(Some(DEADLINE)).unwrap();
        stream.set_write_timeout(Some(DEADLINE)).unwrap();
        let mut client = Self {
            reader: BufReader::new(stream),
            next_id: 0,
        };
        client.request(Command::Hello {
            minimum_version: VERSION,
            maximum_version: VERSION,
        });
        client
    }

    fn request(&mut self, command: Command) -> Value {
        self.next_id += 1;
        let id = self.next_id.to_string();
        let request = Request {
            version: VERSION,
            id: id.clone(),
            command,
        };
        self.reader
            .get_mut()
            .write_all(&encode_line(&request).unwrap())
            .unwrap();
        let mut line = String::new();
        assert!(
            self.reader.read_line(&mut line).unwrap() > 0,
            "unexpected IPC EOF"
        );
        let response: Response = serde_json::from_str(&line).unwrap();
        assert_eq!(response.version, VERSION);
        assert_eq!(response.id, id);
        match response.outcome {
            ResponseOutcome::Ok { result } => result,
            other => panic!("request failed: {other:?}"),
        }
    }

    fn assert_eof(&mut self) {
        assert_eq!(self.reader.read_line(&mut String::new()).unwrap(), 0);
    }
}

#[test]
fn sigterm_drains_clients_and_restart_preserves_identity_and_sealed_outbox() {
    let fixture = Fixture::new();
    let mut daemon = fixture.start();
    let mut first = fixture.client();
    let mut second = fixture.client();
    let before = first.request(Command::Status);
    assert_eq!(second.request(Command::Status), before);
    let sent = first.request(Command::Send {
        conversation: "07e1870bb208e66b5189c2dc7b1c0018e26871920148706534dd74ee5a126ff4".into(),
        text: "private process restart message".into(),
    });
    assert_eq!(sent["delivery"], "queued");
    assert_eq!(second.request(Command::Status)["outbox_pending"], 1);
    let outbox = fixture.dir.path().join("state/records/nostr-outbox-v1");
    let sealed = fs::read(&outbox).unwrap();
    let plaintext = b"private process restart message";
    assert!(
        !sealed
            .windows(plaintext.len())
            .any(|bytes| bytes == plaintext)
    );
    daemon.stop("TERM", &fixture.socket);
    first.assert_eof();
    second.assert_eof();

    let mut restarted = fixture.start();
    let after = fixture.client().request(Command::Status);
    for field in [
        "/fingerprint",
        "/nostr_public_key",
        "/peer_id",
        "/account/account_id",
        "/account/device_id",
    ] {
        let identity = before.pointer(field).and_then(Value::as_str).unwrap();
        assert!(!identity.is_empty(), "empty {field}");
        assert_eq!(
            after.pointer(field).and_then(Value::as_str),
            Some(identity),
            "changed {field}"
        );
    }
    assert_eq!(after["outbox_pending"], 1);
    assert_eq!(after["outbox_failed"], 0);
    assert_eq!(
        fs::read(outbox).unwrap(),
        sealed,
        "restart changed the queued ciphertext"
    );
    restarted.stop("TERM", &fixture.socket);
}

#[test]
fn sigint_without_a_config_file_uses_the_same_clean_shutdown_path() {
    let fixture = Fixture::new();
    let mut daemon = fixture.start_with_config(false);
    let mut client = fixture.client();
    daemon.stop("INT", &fixture.socket);
    client.assert_eof();
}

#[test]
fn sighup_applies_valid_config_and_rejects_invalid_or_restart_only_changes() {
    let fixture = Fixture::new();
    let mut daemon = fixture.start();
    let mut client = fixture.client();
    fixture.configure(json!({"storage_provider":"file", "joined_geohashes":["u4pruy"]}));
    daemon.signal("HUP");
    let start = Instant::now();
    loop {
        if client.request(Command::Status)["joined_geohashes"] == json!(["u4pruy"]) {
            break;
        }
        assert!(start.elapsed() < DEADLINE, "valid reload was not applied");
        thread::sleep(Duration::from_millis(20));
    }
    let before = client.request(Command::Status);
    for (index, invalid) in [
        "{broken JSON".to_owned(),
        json!({"joined_geohashes":["invalid!"]}).to_string(),
        json!({"relays":["wss://relay.example"], "joined_geohashes":["gcpvj"]}).to_string(),
    ]
    .iter()
    .enumerate()
    {
        fs::write(&fixture.config, invalid).unwrap();
        daemon.signal("HUP");
        // Wait for acknowledgement of the rejected signal, not a sleep
        // that could inspect the old state before the reload even happened.
        daemon.wait_for_rejected_reload(index);
        assert_eq!(client.request(Command::Status), before);
        assert_eq!(fixture.client().request(Command::Status), before);
    }
    daemon.stop("TERM", &fixture.socket);
}
