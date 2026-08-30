use secret_service::{EncryptionType, SecretService};
use serde::Serialize;
use std::{
    collections::HashMap,
    env,
    error::Error,
    fs::{self, OpenOptions},
    io::{Read, Write},
    os::unix::fs::{OpenOptionsExt, PermissionsExt},
    path::{Path, PathBuf},
    process::ExitCode,
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{UnixListener, UnixStream},
};

type ProbeError = Box<dyn Error + Send + Sync>;
const MARKER_NAME: &str = "storage-mode";
const SYNTHETIC_SECRET: &[u8] = b"omachat-g0-synthetic-secret";

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
enum StorageMode {
    SecretService,
    File,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum RequestedMode {
    Auto,
    SecretService,
    File,
}

#[derive(Debug, Serialize)]
struct Status {
    active_storage_mode: StorageMode,
    selection: &'static str,
    secret_roundtrip: &'static str,
    socket_mode: Option<String>,
}

struct Arguments {
    requested_mode: RequestedMode,
    state_directory: PathBuf,
    socket_path: Option<PathBuf>,
    status_only: bool,
    serve: bool,
}

#[tokio::main]
async fn main() -> ExitCode {
    match run().await {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("storage lifecycle probe failed: {error}");
            ExitCode::FAILURE
        }
    }
}

async fn run() -> Result<(), ProbeError> {
    let arguments = parse_arguments()?;
    ensure_private_directory(&arguments.state_directory)?;
    let marker = arguments.state_directory.join(MARKER_NAME);
    if arguments.status_only {
        let mode = read_mode(&marker)?.ok_or("storage mode has not been selected")?;
        println!(
            "{}",
            serde_json::to_string_pretty(&status(mode, "existing", "not-run", None))?
        );
        return Ok(());
    }
    let (mode, selection) = select_mode(arguments.requested_mode, &marker).await?;
    match mode {
        StorageMode::SecretService => secret_service_roundtrip().await?,
        StorageMode::File => file_roundtrip(&arguments.state_directory)?,
    }
    if arguments.serve {
        let socket = arguments
            .socket_path
            .as_deref()
            .ok_or("--serve requires --socket-path or RUNTIME_DIRECTORY")?;
        serve_status(socket, mode, selection).await?;
    } else {
        println!(
            "{}",
            serde_json::to_string_pretty(&status(mode, selection, "passed", None))?
        );
    }
    Ok(())
}

fn parse_arguments() -> Result<Arguments, ProbeError> {
    let mut requested_mode = RequestedMode::Auto;
    let mut state_directory = env::var_os("STATE_DIRECTORY").map(PathBuf::from);
    let mut socket_path = env::var_os("RUNTIME_DIRECTORY")
        .map(PathBuf::from)
        .map(|path| path.join("probe.sock"));
    let mut status_only = false;
    let mut serve = false;
    let mut arguments = env::args().skip(1);
    while let Some(argument) = arguments.next() {
        match argument.as_str() {
            "--mode" => {
                requested_mode = match arguments.next().as_deref() {
                    Some("auto") => RequestedMode::Auto,
                    Some("secret-service") => RequestedMode::SecretService,
                    Some("file") => RequestedMode::File,
                    _ => return Err("--mode must be auto, secret-service, or file".into()),
                }
            }
            "--state-dir" => {
                state_directory = Some(
                    arguments
                        .next()
                        .ok_or("--state-dir requires a path")?
                        .into(),
                )
            }
            "--socket-path" => {
                socket_path = Some(
                    arguments
                        .next()
                        .ok_or("--socket-path requires a path")?
                        .into(),
                )
            }
            "--status" => status_only = true,
            "--serve" => serve = true,
            "--help" | "-h" => {
                println!(
                    "usage: storage_lifecycle_probe [--mode auto|secret-service|file] --state-dir PATH [--status] [--serve --socket-path PATH]"
                );
                return Err("help requested".into());
            }
            _ => return Err(format!("unknown argument {argument}").into()),
        }
    }
    Ok(Arguments {
        requested_mode,
        state_directory: state_directory.ok_or("--state-dir or STATE_DIRECTORY is required")?,
        socket_path,
        status_only,
        serve,
    })
}

async fn select_mode(
    requested: RequestedMode,
    marker: &Path,
) -> Result<(StorageMode, &'static str), ProbeError> {
    if let Some(existing) = read_mode(marker)? {
        let matches = matches!(requested, RequestedMode::Auto)
            || matches!(
                (requested, existing),
                (RequestedMode::SecretService, StorageMode::SecretService)
                    | (RequestedMode::File, StorageMode::File)
            );
        if !matches {
            return Err("explicit mode conflicts with the previously selected mode".into());
        }
        return Ok((existing, "existing"));
    }
    let selected = match requested {
        RequestedMode::Auto => {
            if secret_service_ready().await {
                StorageMode::SecretService
            } else {
                StorageMode::File
            }
        }
        RequestedMode::SecretService => {
            if !secret_service_ready().await {
                return Err(
                    "Secret Service is unavailable or its default collection is locked".into(),
                );
            }
            StorageMode::SecretService
        }
        RequestedMode::File => StorageMode::File,
    };
    write_mode(marker, selected)?;
    Ok((selected, "first-run"))
}

async fn secret_service_ready() -> bool {
    let Ok(service) = SecretService::connect(EncryptionType::Dh).await else {
        return false;
    };
    let Ok(collection) = service.get_default_collection().await else {
        return false;
    };
    matches!(collection.is_locked().await, Ok(false))
}

async fn secret_service_roundtrip() -> Result<(), ProbeError> {
    let service = SecretService::connect(EncryptionType::Dh).await?;
    let collection = service.get_default_collection().await?;
    if collection.is_locked().await? {
        return Err("Secret Service default collection is locked".into());
    }
    let pid = std::process::id().to_string();
    let attributes = HashMap::from([
        ("application", "omachat-g0-probe"),
        ("process-id", pid.as_str()),
    ]);
    let item = collection
        .create_item(
            "OmaChat G0 synthetic lifecycle probe",
            attributes,
            SYNTHETIC_SECRET,
            true,
            "application/octet-stream",
        )
        .await?;
    if item.get_secret().await? != SYNTHETIC_SECRET {
        return Err("Secret Service returned different synthetic bytes".into());
    }
    item.delete().await?;
    Ok(())
}

fn file_roundtrip(directory: &Path) -> Result<(), ProbeError> {
    let path = directory.join("synthetic-probe-secret");
    let mut file = OpenOptions::new()
        .create(true)
        .truncate(true)
        .write(true)
        .mode(0o600)
        .open(&path)?;
    fs::set_permissions(&path, fs::Permissions::from_mode(0o600))?;
    file.write_all(SYNTHETIC_SECRET)?;
    file.sync_all()?;
    drop(file);
    let mut recovered = Vec::new();
    OpenOptions::new()
        .read(true)
        .open(&path)?
        .read_to_end(&mut recovered)?;
    if recovered != SYNTHETIC_SECRET {
        return Err("file provider returned different synthetic bytes".into());
    }
    fs::remove_file(path)?;
    Ok(())
}

fn ensure_private_directory(path: &Path) -> Result<(), ProbeError> {
    fs::create_dir_all(path)?;
    fs::set_permissions(path, fs::Permissions::from_mode(0o700))?;
    Ok(())
}

fn read_mode(path: &Path) -> Result<Option<StorageMode>, ProbeError> {
    let value = match fs::read_to_string(path) {
        Ok(value) => value,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(error.into()),
    };
    match value.trim() {
        "secret-service" => Ok(Some(StorageMode::SecretService)),
        "file" => Ok(Some(StorageMode::File)),
        _ => Err("storage mode marker is invalid".into()),
    }
}

fn write_mode(path: &Path, mode: StorageMode) -> Result<(), ProbeError> {
    let temporary = path.with_extension("tmp");
    let mut file = OpenOptions::new()
        .create(true)
        .truncate(true)
        .write(true)
        .mode(0o600)
        .open(&temporary)?;
    fs::set_permissions(&temporary, fs::Permissions::from_mode(0o600))?;
    file.write_all(match mode {
        StorageMode::SecretService => b"secret-service\n",
        StorageMode::File => b"file\n",
    })?;
    file.sync_all()?;
    drop(file);
    fs::rename(temporary, path)?;
    Ok(())
}

fn status(
    mode: StorageMode,
    selection: &'static str,
    secret_roundtrip: &'static str,
    socket_mode: Option<String>,
) -> Status {
    Status {
        active_storage_mode: mode,
        selection,
        secret_roundtrip,
        socket_mode,
    }
}

async fn serve_status(
    socket_path: &Path,
    mode: StorageMode,
    selection: &'static str,
) -> Result<(), ProbeError> {
    if socket_path.exists() {
        fs::remove_file(socket_path)?;
    }
    let listener = UnixListener::bind(socket_path)?;
    fs::set_permissions(socket_path, fs::Permissions::from_mode(0o600))?;
    println!(
        "{}",
        serde_json::to_string_pretty(&status(mode, selection, "passed", Some("0600".to_owned())))?
    );
    loop {
        tokio::select! {
            result = listener.accept() => {
                let (stream, _) = result?;
                handle_status_client(stream, mode, selection).await?;
            }
            result = tokio::signal::ctrl_c() => { result?; break; }
        }
    }
    fs::remove_file(socket_path)?;
    Ok(())
}

async fn handle_status_client(
    mut stream: UnixStream,
    mode: StorageMode,
    selection: &'static str,
) -> Result<(), ProbeError> {
    let mut request = [0_u8; 32];
    let length = stream.read(&mut request).await?;
    if &request[..length] != b"status\n" {
        return Err("probe socket accepts only status newline".into());
    }
    let mut response =
        serde_json::to_vec(&status(mode, selection, "passed", Some("0600".to_owned())))?;
    response.push(b'\n');
    stream.write_all(&response).await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn file_selection_is_sticky_and_mode_0600() -> Result<(), ProbeError> {
        let temporary = tempfile::tempdir()?;
        let state = temporary.path().join("state");
        ensure_private_directory(&state)?;
        let marker = state.join(MARKER_NAME);
        let (mode, selection) = select_mode(RequestedMode::File, &marker).await?;
        assert_eq!(mode, StorageMode::File);
        assert_eq!(selection, "first-run");
        assert_eq!(fs::metadata(&marker)?.permissions().mode() & 0o777, 0o600);
        file_roundtrip(&state)?;
        let (mode, selection) = select_mode(RequestedMode::Auto, &marker).await?;
        assert_eq!(mode, StorageMode::File);
        assert_eq!(selection, "existing");
        assert!(
            select_mode(RequestedMode::SecretService, &marker)
                .await
                .is_err()
        );
        Ok(())
    }
}
