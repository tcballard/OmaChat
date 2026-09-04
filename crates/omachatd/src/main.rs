use omachatd::{DaemonConfig, DaemonCore, EventHub, IpcServer, NostrService};
use std::{env, ffi::OsStr, fs, os::unix::fs::PermissionsExt, path::PathBuf, process::ExitCode};
use tokio::sync::watch;

#[tokio::main]
async fn main() -> ExitCode {
    let arguments = env::args_os().skip(1).collect::<Vec<_>>();
    if arguments.as_slice() == [OsStr::new("--version")] {
        println!("{}", omachat_proto::version_line("omachatd"));
        return ExitCode::SUCCESS;
    }
    let options = match Options::parse(&arguments) {
        Ok(options) => options,
        Err(error) => {
            eprintln!(
                "{error}\nusage: omachatd [--config PATH] [--state PATH] [--socket PATH] [--anchors PATH] [--file-key]"
            );
            return ExitCode::from(2);
        }
    };
    match run(options).await {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("omachatd: {error}");
            ExitCode::from(1)
        }
    }
}

async fn run(options: Options) -> Result<(), Box<dyn std::error::Error>> {
    let mut config = if let Some(path) = &options.config {
        DaemonConfig::load(path)?
    } else {
        DaemonConfig::default()
    };
    if options.file_key {
        config.storage_provider = omachatd::StorageProviderConfig::File;
    }
    if let Some(parent) = options.socket.parent() {
        fs::create_dir_all(parent)?;
        fs::set_permissions(parent, fs::Permissions::from_mode(0o700))?;
    }
    let events = EventHub::default();
    let core = DaemonCore::open(&options.state, config, events.clone()).await?;
    let rooms = core.start_rooms(
        &options.state,
        options.anchor_directory(),
        options.anchors.is_some(),
    )?;
    let (inbound_sender, mut inbound_receiver) = tokio::sync::mpsc::channel(256);
    let geo_relays = core.start_geo_relays(inbound_sender.clone())?;
    let relays = core.relay_urls();
    let nostr = if relays.is_empty() {
        None
    } else {
        let service = NostrService::spawn(&relays, inbound_sender)?;
        let handle = service.handle();
        core.attach_nostr(handle.clone())?;
        let filters = core.nostr_filters(unix_time())?;
        tokio::spawn(async move {
            if let Err(error) = handle.subscribe("omachat-main-v1".into(), filters).await {
                eprintln!("omachatd: initial Nostr subscription failed: {error}");
            }
        });
        Some(service)
    };
    let inbound_core = core.clone();
    tokio::spawn(async move {
        while let Some(notification) = inbound_receiver.recv().await {
            inbound_core.receive_nostr_notification(notification);
        }
    });
    let (dm_inbound_sender, mut dm_inbound_receiver) = tokio::sync::mpsc::channel(256);
    let (dm_ready_sender, mut dm_ready_receiver) = tokio::sync::mpsc::channel(1);
    let dm_inbox = core
        .start_dm_inbox_with_ready(dm_inbound_sender, dm_ready_sender)
        .await?;
    let dm_inbound_core = core.clone();
    tokio::spawn(async move {
        while let Some(event) = dm_inbound_receiver.recv().await {
            dm_inbound_core.receive_dm_inbox_event(event);
        }
    });
    let dm_ready_core = core.clone();
    tokio::spawn(async move {
        while dm_ready_receiver.recv().await.is_some() {
            dm_ready_core.drain_outbox().await;
        }
    });
    if dm_inbox.is_some() {
        let startup_drain = core.clone();
        tokio::spawn(async move { startup_drain.drain_outbox().await });
    }
    let server = IpcServer::bind(&options.socket, core.clone(), events)?;
    let (shutdown_tx, shutdown_rx) = watch::channel(false);

    if let Some(config_path) = options.config.clone() {
        let reload_core = core.clone();
        tokio::spawn(async move {
            let Ok(mut signal) =
                tokio::signal::unix::signal(tokio::signal::unix::SignalKind::hangup())
            else {
                return;
            };
            while signal.recv().await.is_some() {
                if let Err(error) = reload_core.reload(&config_path) {
                    eprintln!("omachatd: rejected SIGHUP reload: {error}");
                }
            }
        });
    }
    let signal_shutdown = shutdown_tx.clone();
    tokio::spawn(async move {
        if tokio::signal::ctrl_c().await.is_ok() {
            let _ = signal_shutdown.send(true);
        }
    });
    let panic_shutdown = shutdown_tx.clone();
    let panic_core = core.clone();
    tokio::spawn(async move {
        panic_core.wait_for_panic_terminal().await;
        let _ = panic_shutdown.send(true);
    });
    let server_result = server.run(shutdown_rx).await;
    core.prepare_for_shutdown().await;
    if let Some(service) = geo_relays {
        service.shutdown().await;
    }
    if let Some(service) = rooms {
        service.shutdown().await;
    }
    if let Some(service) = dm_inbox {
        let _ = service.shutdown().await;
    }
    if let Some(service) = nostr {
        let _ = service.shutdown().await;
    }
    server_result?;
    Ok(())
}

fn unix_time() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |duration| duration.as_secs())
}

struct Options {
    config: Option<PathBuf>,
    state: PathBuf,
    socket: PathBuf,
    anchors: Option<PathBuf>,
    file_key: bool,
}

impl Options {
    /// Room-state anchors live beside, never inside, the sealed state
    /// directory so restoring that directory from backup cannot rewind them.
    fn anchor_directory(&self) -> PathBuf {
        if let Some(anchors) = &self.anchors {
            return anchors.clone();
        }
        let mut name = self.state.file_name().map_or_else(
            || std::ffi::OsString::from("omachat"),
            std::ffi::OsStr::to_os_string,
        );
        name.push("-anchors");
        self.state.with_file_name(name)
    }

    fn parse(arguments: &[std::ffi::OsString]) -> Result<Self, String> {
        let state = env::var_os("XDG_STATE_HOME")
            .map(PathBuf::from)
            .or_else(|| env::var_os("HOME").map(|home| PathBuf::from(home).join(".local/state")))
            .ok_or("XDG_STATE_HOME and HOME are unset")?
            .join("omachat");
        let socket = env::var_os("XDG_RUNTIME_DIR")
            .map(PathBuf::from)
            .ok_or("XDG_RUNTIME_DIR is unset")?
            .join("omachat/omachat.sock");
        let mut options = Self {
            config: None,
            state,
            socket,
            anchors: None,
            file_key: false,
        };
        let mut index = 0;
        while index < arguments.len() {
            match arguments[index].to_str() {
                Some("--config" | "--state" | "--socket" | "--anchors") => {
                    let flag = arguments[index].to_string_lossy().into_owned();
                    let value = arguments
                        .get(index + 1)
                        .ok_or_else(|| format!("{flag} requires a path"))?;
                    match flag.as_str() {
                        "--config" => options.config = Some(PathBuf::from(value)),
                        "--state" => options.state = PathBuf::from(value),
                        "--socket" => options.socket = PathBuf::from(value),
                        "--anchors" => options.anchors = Some(PathBuf::from(value)),
                        _ => unreachable!(),
                    }
                    index += 2;
                }
                Some("--file-key") => {
                    options.file_key = true;
                    index += 1;
                }
                _ => return Err("unknown or non-UTF-8 argument".into()),
            }
        }
        Ok(options)
    }
}
