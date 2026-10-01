use omachatd::{DaemonConfig, DaemonCore, EventHub, IpcServer};
use std::{env, ffi::OsStr, fs, os::unix::fs::PermissionsExt, path::PathBuf, process::ExitCode};
use tokio::signal::unix::{SignalKind, signal};
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
                "{error}\nusage: omachatd [--config PATH] [--state PATH] [--socket PATH] [--file-key]"
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
    // Install handlers before publishing the IPC socket. Once a client can
    // observe readiness, both terminal interrupts and systemd's SIGTERM must
    // reach the same draining/cleanup path. Registration failure is fatal.
    let mut interrupt = signal(SignalKind::interrupt())?;
    let mut terminate = signal(SignalKind::terminate())?;
    let reload_signal = options
        .config
        .as_ref()
        .map(|path| signal(SignalKind::hangup()).map(|signal| (path.clone(), signal)))
        .transpose()?;
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
    let hosted = core.start_hosted()?;
    let server = IpcServer::bind(&options.socket, core.clone(), events)?;
    let (shutdown_tx, shutdown_rx) = watch::channel(false);

    let reload_task = reload_signal.map(|(config_path, mut signal)| {
        let reload_core = core.clone();
        tokio::spawn(async move {
            while signal.recv().await.is_some() {
                if let Err(error) = reload_core.reload(&config_path) {
                    eprintln!("omachatd: rejected SIGHUP reload: {error}");
                }
            }
        })
    });
    let signal_shutdown = shutdown_tx.clone();
    let signal_task = tokio::spawn(async move {
        tokio::select! {
            _ = interrupt.recv() => {},
            _ = terminate.recv() => {},
        }
        let _ = signal_shutdown.send(true);
    });
    let panic_shutdown = shutdown_tx.clone();
    let panic_core = core.clone();
    tokio::spawn(async move {
        panic_core.wait_for_panic_terminal().await;
        let _ = panic_shutdown.send(true);
    });
    let server_result = server.run(shutdown_rx).await;
    // Join cancellation before dismantling services so SIGHUP cannot race
    // shutdown by applying a new configuration or restarting subscriptions.
    if let Some(task) = reload_task {
        task.abort();
        let _ = task.await;
    }
    signal_task.abort();
    let _ = signal_task.await;
    core.prepare_for_shutdown().await;
    if let Some(service) = hosted {
        service.shutdown().await;
    }
    server_result?;
    Ok(())
}

struct Options {
    config: Option<PathBuf>,
    state: PathBuf,
    socket: PathBuf,
    file_key: bool,
}

impl Options {
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
        let config = env::var_os("XDG_CONFIG_HOME")
            .map(PathBuf::from)
            .or_else(|| env::var_os("HOME").map(|home| PathBuf::from(home).join(".config")))
            .map(|root| root.join("omachat/config.json"))
            .filter(|path| path.exists());
        let mut options = Self {
            config,
            state,
            socket,
            file_key: false,
        };
        let mut index = 0;
        while index < arguments.len() {
            match arguments[index].to_str() {
                Some("--config" | "--state" | "--socket") => {
                    let flag = arguments[index].to_string_lossy().into_owned();
                    let value = arguments
                        .get(index + 1)
                        .ok_or_else(|| format!("{flag} requires a path"))?;
                    match flag.as_str() {
                        "--config" => options.config = Some(PathBuf::from(value)),
                        "--state" => options.state = PathBuf::from(value),
                        "--socket" => options.socket = PathBuf::from(value),
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
