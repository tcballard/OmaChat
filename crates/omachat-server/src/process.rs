use crate::host::HostLimits;
use std::{error::Error, ffi::OsString, fmt, net::SocketAddr, path::PathBuf, time::Duration};

const DEFAULT_LISTEN: &str = "127.0.0.1:7448";

pub const SERVERD_HELP: &str = "\
Usage: omachat-serverd --data-dir PATH --server-key-file PATH --storage-key-file PATH [OPTIONS]\n\
       omachat-serverd --generate-secret PATH\n\
\n\
Required:\n\
  --data-dir PATH                 Directory holding server.db (created 0700)\n\
  --server-key-file PATH          Owner-only file: 64 hex chars, Ed25519 server identity seed\n\
  --storage-key-file PATH         Owner-only file: 64 hex chars, database key-check key\n\
\n\
Options:\n\
  --listen ADDRESS                Loopback listener (default: 127.0.0.1:7448)\n\
  --nip05-relay URL               Repeatable wss:// or ws:// URL included in NIP-05\n\
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
pub struct ServerProcessConfig {
    pub data_dir: PathBuf,
    pub server_key_file: PathBuf,
    pub storage_key_file: PathBuf,
    pub listen: SocketAddr,
    pub limits: HostLimits,
    pub nip05_relays: Vec<String>,
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
    let mut listen = None;
    let mut nip05_relays = Vec::new();
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
            "--nip05-relay" => {
                let value = parse_utf8(
                    next_value(&mut arguments, "--nip05-relay")?,
                    "--nip05-relay",
                )?;
                if nip05_relays.len() >= 8
                    || !(value.starts_with("wss://") || value.starts_with("ws://"))
                    || value.len() > 256
                    || value.chars().any(char::is_whitespace)
                {
                    return Err(ServerProcessConfigError::InvalidValue("--nip05-relay"));
                }
                nip05_relays.push(value);
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
        listen,
        limits,
        nip05_relays,
    }))
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
        }
    }
}

impl Error for ServerProcessConfigError {}

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
        assert_eq!(config.limits.max_connections, 10);
        assert_eq!(config.limits.session.idle_timeout, Duration::from_secs(60));
        assert_eq!(config.listen.port(), 9000);
    }

    #[test]
    fn rejects_incomplete_or_unsafe_configurations() {
        assert!(matches!(
            parse_server_process_args(args(&["--data-dir", "/tmp/d"])),
            Err(ServerProcessConfigError::Missing("--server-key-file"))
        ));
        assert!(matches!(
            parse_server_process_args(args(&[
                "--data-dir",
                "/tmp/d",
                "--server-key-file",
                "/tmp/s",
                "--storage-key-file",
                "/tmp/k",
                "--listen",
                "0.0.0.0:7448",
            ])),
            Err(ServerProcessConfigError::NonLoopbackListen(_))
        ));
        assert!(matches!(
            parse_server_process_args(args(&[
                "--data-dir",
                "/tmp/d",
                "--server-key-file",
                "/tmp/s",
                "--storage-key-file",
                "/tmp/k",
                "--max-connections",
                "1",
                "--max-connections-per-ip",
                "2",
            ])),
            Err(ServerProcessConfigError::InvalidValue("limits"))
        ));
        assert!(matches!(
            parse_server_process_args(args(&["--generate-secret", "/tmp/x"])),
            Ok(ServerProcessCommand::GenerateSecret(_))
        ));
        assert!(matches!(
            parse_server_process_args(args(&[
                "--data-dir",
                "/tmp/d",
                "--server-key-file",
                "/tmp/s",
                "--storage-key-file",
                "/tmp/k",
                "--registration",
                "invite",
            ])),
            Err(ServerProcessConfigError::UnknownOption(_))
        ));
    }
}
