//! Command-line configuration for `omachat-serverd`.

use crate::{host::HostLimits, protocol::MAX_INVITE_CODE_BYTES, service::Registration};
use std::{
    error::Error,
    ffi::OsString,
    fmt,
    fs::File,
    io::Read,
    net::SocketAddr,
    os::unix::fs::PermissionsExt,
    path::{Path, PathBuf},
    time::Duration,
};

const DEFAULT_LISTEN: &str = "127.0.0.1:7448";

pub const SERVERD_HELP: &str = "\
Usage: omachat-serverd --data-dir PATH --server-key-file PATH --storage-key-file PATH \\
                       --registration open|invite|closed [OPTIONS]\n\
       omachat-serverd --generate-secret PATH\n\
\n\
Required:\n\
  --data-dir PATH                 Directory holding messages.db (created 0700)\n\
  --server-key-file PATH          Owner-only file: 64 hex chars, Ed25519 server identity seed\n\
  --storage-key-file PATH         Owner-only file: 64 hex chars, at-rest message key\n\
  --registration MODE             open: any device may register\n\
                                  invite: requires --invite-code-file\n\
                                  closed: only known devices may authenticate\n\
\n\
Options:\n\
  --invite-code-file PATH         Owner-only file with one invite code per line\n\
  --listen ADDRESS                Loopback listener (default: 127.0.0.1:7448)\n\
  --max-connections N             Global connection limit (default: 1024)\n\
  --max-connections-per-ip N      Per-IP connection limit (default: 32)\n\
  --idle-timeout-seconds N        Close silent connections (default: 300)\n\
  --shutdown-grace-seconds N      Graceful drain timeout (default: 10)\n\
  --generate-secret PATH          Write a new owner-only 64-hex secret file and exit\n\
  --help                          Show this help\n\
  --version                       Show the package version\n\
\n\
Network: loopback only; expose only through a TLS reverse proxy.\n";

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum RegistrationMode {
    Open,
    Invite,
    Closed,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ServerProcessConfig {
    pub data_dir: PathBuf,
    pub server_key_file: PathBuf,
    pub storage_key_file: PathBuf,
    pub registration: RegistrationMode,
    pub invite_code_file: Option<PathBuf>,
    pub listen: SocketAddr,
    pub limits: HostLimits,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ServerProcessCommand {
    Run(ServerProcessConfig),
    GenerateSecret(PathBuf),
    Help,
    Version,
}

pub fn parse_server_process_args(
    args: impl IntoIterator<Item = OsString>,
) -> Result<ServerProcessCommand, ServerProcessConfigError> {
    let mut arguments = args.into_iter();
    let _program = arguments.next();
    let remaining: Vec<OsString> = arguments.collect();
    if remaining.len() == 1 {
        if remaining[0] == "--help" {
            return Ok(ServerProcessCommand::Help);
        }
        if remaining[0] == "--version" {
            return Ok(ServerProcessCommand::Version);
        }
    }
    if remaining.len() == 2 && remaining[0] == "--generate-secret" {
        return Ok(ServerProcessCommand::GenerateSecret(PathBuf::from(
            remaining[1].clone(),
        )));
    }

    let mut arguments = remaining.into_iter();
    let mut data_dir = None;
    let mut server_key_file = None;
    let mut storage_key_file = None;
    let mut registration = None;
    let mut invite_code_file = None;
    let mut listen = None;
    let mut limits = HostLimits::default();
    let mut seen_max_connections = None;
    let mut seen_per_ip = None;
    let mut seen_idle = None;
    let mut seen_grace = None;
    while let Some(option) = arguments.next() {
        let option = option
            .to_str()
            .ok_or(ServerProcessConfigError::NonUtf8Option)?;
        match option {
            "--data-dir" => set_once(
                &mut data_dir,
                PathBuf::from(next_value(&mut arguments, "--data-dir")?),
                "--data-dir",
            )?,
            "--server-key-file" => set_once(
                &mut server_key_file,
                PathBuf::from(next_value(&mut arguments, "--server-key-file")?),
                "--server-key-file",
            )?,
            "--storage-key-file" => set_once(
                &mut storage_key_file,
                PathBuf::from(next_value(&mut arguments, "--storage-key-file")?),
                "--storage-key-file",
            )?,
            "--invite-code-file" => set_once(
                &mut invite_code_file,
                PathBuf::from(next_value(&mut arguments, "--invite-code-file")?),
                "--invite-code-file",
            )?,
            "--registration" => {
                let value = parse_utf8(
                    next_value(&mut arguments, "--registration")?,
                    "--registration",
                )?;
                let mode = match value.as_str() {
                    "open" => RegistrationMode::Open,
                    "invite" => RegistrationMode::Invite,
                    "closed" => RegistrationMode::Closed,
                    _ => return Err(ServerProcessConfigError::InvalidValue("--registration")),
                };
                set_once(&mut registration, mode, "--registration")?;
            }
            "--listen" => {
                let value = parse_utf8(next_value(&mut arguments, "--listen")?, "--listen")?;
                let address: SocketAddr = value
                    .parse()
                    .map_err(|_| ServerProcessConfigError::InvalidValue("--listen"))?;
                set_once(&mut listen, address, "--listen")?;
            }
            "--max-connections" => {
                let value = parse_number(
                    next_value(&mut arguments, "--max-connections")?,
                    "--max-connections",
                )?;
                set_once(&mut seen_max_connections, value, "--max-connections")?;
                limits.max_connections = usize::try_from(value)
                    .map_err(|_| ServerProcessConfigError::InvalidValue("--max-connections"))?;
            }
            "--max-connections-per-ip" => {
                let value = parse_number(
                    next_value(&mut arguments, "--max-connections-per-ip")?,
                    "--max-connections-per-ip",
                )?;
                set_once(&mut seen_per_ip, value, "--max-connections-per-ip")?;
                limits.max_connections_per_ip = usize::try_from(value).map_err(|_| {
                    ServerProcessConfigError::InvalidValue("--max-connections-per-ip")
                })?;
            }
            "--idle-timeout-seconds" => {
                let value = parse_number(
                    next_value(&mut arguments, "--idle-timeout-seconds")?,
                    "--idle-timeout-seconds",
                )?;
                set_once(&mut seen_idle, value, "--idle-timeout-seconds")?;
                limits.session.idle_timeout = Duration::from_secs(value);
            }
            "--shutdown-grace-seconds" => {
                let value = parse_number(
                    next_value(&mut arguments, "--shutdown-grace-seconds")?,
                    "--shutdown-grace-seconds",
                )?;
                set_once(&mut seen_grace, value, "--shutdown-grace-seconds")?;
                limits.shutdown_grace = Duration::from_secs(value);
            }
            other => return Err(ServerProcessConfigError::UnknownOption(other.to_owned())),
        }
    }
    let registration = registration.ok_or(ServerProcessConfigError::Missing("--registration"))?;
    if registration == RegistrationMode::Invite && invite_code_file.is_none() {
        return Err(ServerProcessConfigError::Missing("--invite-code-file"));
    }
    if registration != RegistrationMode::Invite && invite_code_file.is_some() {
        return Err(ServerProcessConfigError::InvalidValue("--invite-code-file"));
    }
    let listen = listen.unwrap_or_else(|| {
        DEFAULT_LISTEN
            .parse()
            .expect("default listen address is valid")
    });
    if !listen.ip().is_loopback() {
        return Err(ServerProcessConfigError::NonLoopbackListen(listen));
    }
    limits
        .validate()
        .map_err(|_| ServerProcessConfigError::InvalidValue("limits"))?;
    Ok(ServerProcessCommand::Run(ServerProcessConfig {
        data_dir: data_dir.ok_or(ServerProcessConfigError::Missing("--data-dir"))?,
        server_key_file: server_key_file
            .ok_or(ServerProcessConfigError::Missing("--server-key-file"))?,
        storage_key_file: storage_key_file
            .ok_or(ServerProcessConfigError::Missing("--storage-key-file"))?,
        registration,
        invite_code_file,
        listen,
        limits,
    }))
}

/// Read invite codes from an owner-only file, one per line.
pub fn load_invite_codes(path: &Path) -> Result<Registration, ServerProcessConfigError> {
    let mut file = File::open(path).map_err(|source| ServerProcessConfigError::InviteIo {
        path: path.to_owned(),
        source,
    })?;
    let metadata = file
        .metadata()
        .map_err(|source| ServerProcessConfigError::InviteIo {
            path: path.to_owned(),
            source,
        })?;
    if !metadata.is_file() {
        return Err(ServerProcessConfigError::InviteNotRegular(path.to_owned()));
    }
    let mode = metadata.permissions().mode() & 0o777;
    if mode & 0o077 != 0 {
        return Err(ServerProcessConfigError::InvitePermissions {
            path: path.to_owned(),
            mode,
        });
    }
    if metadata.len() > 64 * 1024 {
        return Err(ServerProcessConfigError::InviteTooLarge(path.to_owned()));
    }
    let mut contents = String::new();
    file.read_to_string(&mut contents)
        .map_err(|source| ServerProcessConfigError::InviteIo {
            path: path.to_owned(),
            source,
        })?;
    if contents
        .lines()
        .any(|line| line.trim().len() > MAX_INVITE_CODE_BYTES)
    {
        return Err(ServerProcessConfigError::InviteTooLarge(path.to_owned()));
    }
    Registration::invite_codes(contents.lines().map(str::to_owned))
        .map_err(|_| ServerProcessConfigError::InviteEmpty(path.to_owned()))
}

fn next_value(
    arguments: &mut impl Iterator<Item = OsString>,
    option: &'static str,
) -> Result<OsString, ServerProcessConfigError> {
    arguments
        .next()
        .ok_or(ServerProcessConfigError::MissingValue(option))
}

fn parse_utf8(value: OsString, option: &'static str) -> Result<String, ServerProcessConfigError> {
    value
        .into_string()
        .map_err(|_| ServerProcessConfigError::InvalidValue(option))
}

fn parse_number(value: OsString, option: &'static str) -> Result<u64, ServerProcessConfigError> {
    parse_utf8(value, option)?
        .parse::<u64>()
        .map_err(|_| ServerProcessConfigError::InvalidValue(option))
}

fn set_once<T>(
    slot: &mut Option<T>,
    value: T,
    option: &'static str,
) -> Result<(), ServerProcessConfigError> {
    if slot.is_some() {
        return Err(ServerProcessConfigError::Repeated(option));
    }
    *slot = Some(value);
    Ok(())
}

#[derive(Debug)]
pub enum ServerProcessConfigError {
    NonUtf8Option,
    UnknownOption(String),
    MissingValue(&'static str),
    InvalidValue(&'static str),
    Repeated(&'static str),
    Missing(&'static str),
    NonLoopbackListen(SocketAddr),
    InviteIo {
        path: PathBuf,
        source: std::io::Error,
    },
    InviteNotRegular(PathBuf),
    InvitePermissions {
        path: PathBuf,
        mode: u32,
    },
    InviteTooLarge(PathBuf),
    InviteEmpty(PathBuf),
}

impl fmt::Display for ServerProcessConfigError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NonUtf8Option => formatter.write_str("options must be UTF-8"),
            Self::UnknownOption(option) => write!(formatter, "unknown option {option}"),
            Self::MissingValue(option) => write!(formatter, "{option} needs a value"),
            Self::InvalidValue(option) => write!(formatter, "{option} has an invalid value"),
            Self::Repeated(option) => write!(formatter, "{option} was given more than once"),
            Self::Missing(option) => write!(formatter, "{option} is required"),
            Self::NonLoopbackListen(address) => write!(
                formatter,
                "--listen {address} is not loopback; expose the server through a TLS reverse proxy"
            ),
            Self::InviteIo { path, source } => write!(formatter, "{}: {source}", path.display()),
            Self::InviteNotRegular(path) => {
                write!(formatter, "{} is not a regular file", path.display())
            }
            Self::InvitePermissions { path, mode } => write!(
                formatter,
                "{} has mode {mode:o}; it must be readable by its owner only",
                path.display()
            ),
            Self::InviteTooLarge(path) => write!(
                formatter,
                "{} is too large or has a code over 128 bytes",
                path.display()
            ),
            Self::InviteEmpty(path) => {
                write!(formatter, "{} holds no invite codes", path.display())
            }
        }
    }
}

impl Error for ServerProcessConfigError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::InviteIo { source, .. } => Some(source),
            _ => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn args(list: &[&str]) -> Vec<OsString> {
        std::iter::once("omachat-serverd")
            .chain(list.iter().copied())
            .map(OsString::from)
            .collect()
    }

    #[test]
    fn parses_a_full_run_configuration() {
        let command = parse_server_process_args(args(&[
            "--data-dir",
            "/tmp/d",
            "--server-key-file",
            "/tmp/s",
            "--storage-key-file",
            "/tmp/k",
            "--registration",
            "invite",
            "--invite-code-file",
            "/tmp/i",
            "--listen",
            "127.0.0.1:9000",
            "--max-connections",
            "10",
            "--max-connections-per-ip",
            "2",
            "--idle-timeout-seconds",
            "60",
        ]))
        .unwrap();
        let ServerProcessCommand::Run(config) = command else {
            panic!("expected run");
        };
        assert_eq!(config.registration, RegistrationMode::Invite);
        assert_eq!(config.limits.max_connections, 10);
        assert_eq!(config.limits.session.idle_timeout, Duration::from_secs(60));
    }

    #[test]
    fn rejects_incomplete_or_unsafe_configurations() {
        let base = [
            "--data-dir",
            "/tmp/d",
            "--server-key-file",
            "/tmp/s",
            "--storage-key-file",
            "/tmp/k",
        ];
        assert!(matches!(
            parse_server_process_args(args(&base)),
            Err(ServerProcessConfigError::Missing("--registration"))
        ));
        let mut invite = base.to_vec();
        invite.extend(["--registration", "invite"]);
        assert!(matches!(
            parse_server_process_args(args(&invite)),
            Err(ServerProcessConfigError::Missing("--invite-code-file"))
        ));
        let mut public = base.to_vec();
        public.extend(["--registration", "open", "--listen", "0.0.0.0:7448"]);
        assert!(matches!(
            parse_server_process_args(args(&public)),
            Err(ServerProcessConfigError::NonLoopbackListen(_))
        ));
        let mut per_ip = base.to_vec();
        per_ip.extend([
            "--registration",
            "open",
            "--max-connections",
            "1",
            "--max-connections-per-ip",
            "2",
        ]);
        assert!(matches!(
            parse_server_process_args(args(&per_ip)),
            Err(ServerProcessConfigError::InvalidValue("limits"))
        ));
        assert!(matches!(
            parse_server_process_args(args(&["--generate-secret", "/tmp/x"])),
            Ok(ServerProcessCommand::GenerateSecret(_))
        ));
    }

    #[test]
    fn invite_files_must_be_owner_only_and_non_empty() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("invites");
        std::fs::write(&path, "alpha\n\n beta \n").unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();
        assert!(matches!(
            load_invite_codes(&path),
            Err(ServerProcessConfigError::InvitePermissions { .. })
        ));
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
        let Registration::Invite(codes) = load_invite_codes(&path).unwrap() else {
            panic!("expected invite mode");
        };
        assert_eq!(codes.len(), 2);
        assert!(codes.contains("beta"));
        let empty = directory.path().join("empty");
        std::fs::write(&empty, "\n").unwrap();
        std::fs::set_permissions(&empty, std::fs::Permissions::from_mode(0o600)).unwrap();
        assert!(matches!(
            load_invite_codes(&empty),
            Err(ServerProcessConfigError::InviteEmpty(_))
        ));
    }
}
