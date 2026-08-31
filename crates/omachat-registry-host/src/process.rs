use crate::{RegistryHostError, RegistryHostLimits};
use rustix::fs::{Mode, OFlags, open};
use std::{
    error::Error,
    ffi::OsString,
    fmt,
    fs::File,
    io::Read,
    net::SocketAddr,
    os::unix::fs::PermissionsExt,
    path::{Path, PathBuf},
    time::{Duration, SystemTime, UNIX_EPOCH},
};
use zeroize::Zeroizing;

const DEFAULT_LISTEN: &str = "127.0.0.1:7447";

pub const REGISTRYD_HELP: &str = "\
Usage: omachat-registryd --data-dir PATH --signing-seed-file PATH [OPTIONS]\n\
\n\
Required:\n\
  --data-dir PATH                 Sealed registry state directory\n\
  --signing-seed-file PATH        Owner-only file containing 64 hex characters\n\
\n\
Options:\n\
  --listen ADDRESS                Loopback listener (default: 127.0.0.1:7447)\n\
  --max-connections N             Global in-flight limit (default: 128)\n\
  --max-connections-per-ip N      Per-IP in-flight limit (default: 8)\n\
  --request-timeout-seconds N     Handshake/request timeout (default: 10)\n\
  --shutdown-grace-seconds N      Graceful drain timeout (default: 10)\n\
  --help                          Show this help\n\
  --version                       Show the package version\n\
\n\
Network: loopback only; expose only through a TLS reverse proxy.\n";

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RegistryProcessConfig {
    pub data_dir: PathBuf,
    pub signing_seed_file: PathBuf,
    pub listen: SocketAddr,
    pub limits: RegistryHostLimits,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum RegistryProcessCommand {
    Run(RegistryProcessConfig),
    Help,
    Version,
}

#[derive(Debug, Default)]
pub struct RegistryAcceptanceClock {
    previous: Option<u64>,
}

impl RegistryAcceptanceClock {
    #[must_use]
    pub const fn new() -> Self {
        Self { previous: None }
    }

    pub fn now(&mut self) -> Result<u64, RegistryHostError> {
        let current = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|_| RegistryHostError::ClockBeforeUnixEpoch)?
            .as_secs();
        self.observe(current)
    }

    pub fn observe(&mut self, current: u64) -> Result<u64, RegistryHostError> {
        if let Some(previous) = self.previous
            && current < previous
        {
            return Err(RegistryHostError::ClockRollback { previous, current });
        }
        self.previous = Some(current);
        Ok(current)
    }
}

pub fn parse_registry_process_args(
    args: impl IntoIterator<Item = OsString>,
) -> Result<RegistryProcessCommand, RegistryProcessConfigError> {
    let mut arguments = args.into_iter();
    let _program = arguments.next();
    let remaining: Vec<OsString> = arguments.collect();
    if remaining.len() == 1 {
        if remaining[0] == "--help" {
            return Ok(RegistryProcessCommand::Help);
        }
        if remaining[0] == "--version" {
            return Ok(RegistryProcessCommand::Version);
        }
    }

    let mut arguments = remaining.into_iter();
    let mut data_dir = None;
    let mut signing_seed_file = None;
    let mut listen = None;
    let mut max_connections = None;
    let mut max_connections_per_ip = None;
    let mut request_timeout_seconds = None;
    let mut shutdown_grace_seconds = None;
    while let Some(option) = arguments.next() {
        let option = option
            .to_str()
            .ok_or(RegistryProcessConfigError::NonUtf8Option)?;
        match option {
            "--data-dir" => set_once(
                &mut data_dir,
                next_value(&mut arguments, "--data-dir")?,
                "--data-dir",
            )?,
            "--signing-seed-file" => set_once(
                &mut signing_seed_file,
                next_value(&mut arguments, "--signing-seed-file")?,
                "--signing-seed-file",
            )?,
            "--listen" => {
                let value = parse_utf8(next_value(&mut arguments, "--listen")?, "--listen")?;
                let address: SocketAddr = value
                    .parse()
                    .map_err(|_| RegistryProcessConfigError::InvalidValue("--listen"))?;
                set_once(&mut listen, address, "--listen")?;
            }
            "--max-connections" => {
                let value = parse_usize(
                    next_value(&mut arguments, "--max-connections")?,
                    "--max-connections",
                )?;
                set_once(&mut max_connections, value, "--max-connections")?;
            }
            "--max-connections-per-ip" => {
                let value = parse_usize(
                    next_value(&mut arguments, "--max-connections-per-ip")?,
                    "--max-connections-per-ip",
                )?;
                set_once(
                    &mut max_connections_per_ip,
                    value,
                    "--max-connections-per-ip",
                )?;
            }
            "--request-timeout-seconds" => {
                let value = parse_u64(
                    next_value(&mut arguments, "--request-timeout-seconds")?,
                    "--request-timeout-seconds",
                )?;
                set_once(
                    &mut request_timeout_seconds,
                    value,
                    "--request-timeout-seconds",
                )?;
            }
            "--shutdown-grace-seconds" => {
                let value = parse_u64(
                    next_value(&mut arguments, "--shutdown-grace-seconds")?,
                    "--shutdown-grace-seconds",
                )?;
                set_once(
                    &mut shutdown_grace_seconds,
                    value,
                    "--shutdown-grace-seconds",
                )?;
            }
            "--help" => return Err(RegistryProcessConfigError::StandaloneOption("--help")),
            "--version" => {
                return Err(RegistryProcessConfigError::StandaloneOption("--version"));
            }
            _ => return Err(RegistryProcessConfigError::UnknownOption(option.to_owned())),
        }
    }

    let data_dir = data_dir.ok_or(RegistryProcessConfigError::MissingRequired("--data-dir"))?;
    let signing_seed_file = signing_seed_file.ok_or(
        RegistryProcessConfigError::MissingRequired("--signing-seed-file"),
    )?;
    let listen = listen.unwrap_or_else(|| {
        DEFAULT_LISTEN
            .parse()
            .expect("committed registry listen default must be valid")
    });
    if !listen.ip().is_loopback() {
        return Err(RegistryProcessConfigError::NonLoopbackListen(listen));
    }
    let limits = RegistryHostLimits {
        max_connections: max_connections.unwrap_or(128),
        max_connections_per_ip: max_connections_per_ip.unwrap_or(8),
        request_admission_timeout: Duration::from_secs(request_timeout_seconds.unwrap_or(10)),
        shutdown_grace: Duration::from_secs(shutdown_grace_seconds.unwrap_or(10)),
    }
    .validate()
    .map_err(|_| RegistryProcessConfigError::InvalidLimits)?;

    Ok(RegistryProcessCommand::Run(RegistryProcessConfig {
        data_dir: data_dir.into(),
        signing_seed_file: signing_seed_file.into(),
        listen,
        limits,
    }))
}

/// Load a registry signing seed without following symlinks. The file must be a
/// regular owner-only file containing exactly 64 hexadecimal characters and an
/// optional single trailing line feed.
pub fn load_registry_signing_seed(
    path: &Path,
) -> Result<Zeroizing<[u8; 32]>, RegistryProcessConfigError> {
    let descriptor = open(
        path,
        OFlags::RDONLY | OFlags::CLOEXEC | OFlags::NOFOLLOW,
        Mode::empty(),
    )
    .map_err(|error| RegistryProcessConfigError::SeedIo {
        path: path.to_owned(),
        source: std::io::Error::from_raw_os_error(error.raw_os_error()),
    })?;
    let mut file = File::from(descriptor);
    let metadata = file
        .metadata()
        .map_err(|source| RegistryProcessConfigError::SeedIo {
            path: path.to_owned(),
            source,
        })?;
    if !metadata.is_file() {
        return Err(RegistryProcessConfigError::SeedNotRegular(path.to_owned()));
    }
    let mode = metadata.permissions().mode() & 0o777;
    if mode & 0o077 != 0 {
        return Err(RegistryProcessConfigError::SeedPermissions { mode });
    }
    if metadata.len() > 65 {
        return Err(RegistryProcessConfigError::SeedEncoding);
    }

    let mut encoded = Zeroizing::new(Vec::with_capacity(65));
    file.read_to_end(&mut encoded)
        .map_err(|source| RegistryProcessConfigError::SeedIo {
            path: path.to_owned(),
            source,
        })?;
    let encoded = encoded.strip_suffix(b"\n").unwrap_or(encoded.as_slice());
    if encoded.len() != 64 || !encoded.iter().all(u8::is_ascii_hexdigit) {
        return Err(RegistryProcessConfigError::SeedEncoding);
    }
    let mut seed = Zeroizing::new([0_u8; 32]);
    hex::decode_to_slice(encoded, seed.as_mut())
        .map_err(|_| RegistryProcessConfigError::SeedEncoding)?;
    Ok(seed)
}

fn next_value(
    arguments: &mut impl Iterator<Item = OsString>,
    option: &'static str,
) -> Result<OsString, RegistryProcessConfigError> {
    arguments
        .next()
        .ok_or(RegistryProcessConfigError::MissingValue(option))
}

fn parse_utf8(value: OsString, option: &'static str) -> Result<String, RegistryProcessConfigError> {
    value
        .into_string()
        .map_err(|_| RegistryProcessConfigError::InvalidValue(option))
}

fn parse_usize(value: OsString, option: &'static str) -> Result<usize, RegistryProcessConfigError> {
    parse_utf8(value, option)?
        .parse()
        .map_err(|_| RegistryProcessConfigError::InvalidValue(option))
}

fn parse_u64(value: OsString, option: &'static str) -> Result<u64, RegistryProcessConfigError> {
    parse_utf8(value, option)?
        .parse()
        .map_err(|_| RegistryProcessConfigError::InvalidValue(option))
}

fn set_once<T>(
    target: &mut Option<T>,
    value: T,
    option: &'static str,
) -> Result<(), RegistryProcessConfigError> {
    if target.replace(value).is_some() {
        return Err(RegistryProcessConfigError::DuplicateOption(option));
    }
    Ok(())
}

#[derive(Debug)]
pub enum RegistryProcessConfigError {
    NonUtf8Option,
    UnknownOption(String),
    StandaloneOption(&'static str),
    MissingValue(&'static str),
    MissingRequired(&'static str),
    DuplicateOption(&'static str),
    InvalidValue(&'static str),
    InvalidLimits,
    NonLoopbackListen(SocketAddr),
    SeedIo {
        path: PathBuf,
        source: std::io::Error,
    },
    SeedNotRegular(PathBuf),
    SeedPermissions {
        mode: u32,
    },
    SeedEncoding,
}

impl fmt::Display for RegistryProcessConfigError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NonUtf8Option => formatter.write_str("registry option name is not valid UTF-8"),
            Self::UnknownOption(option) => write!(formatter, "unknown registry option {option}"),
            Self::StandaloneOption(option) => {
                write!(formatter, "registry option {option} must be used alone")
            }
            Self::MissingValue(option) => {
                write!(formatter, "registry option {option} needs a value")
            }
            Self::MissingRequired(option) => {
                write!(formatter, "required registry option {option} is missing")
            }
            Self::DuplicateOption(option) => {
                write!(
                    formatter,
                    "registry option {option} was provided more than once"
                )
            }
            Self::InvalidValue(option) => write!(formatter, "registry option {option} is invalid"),
            Self::InvalidLimits => formatter.write_str("registry process limits are invalid"),
            Self::NonLoopbackListen(address) => {
                write!(
                    formatter,
                    "registry listen address {address} is not loopback"
                )
            }
            Self::SeedIo { path, source } => {
                write!(
                    formatter,
                    "registry seed file {} failed: {source}",
                    path.display()
                )
            }
            Self::SeedNotRegular(path) => {
                write!(
                    formatter,
                    "registry seed file {} is not regular",
                    path.display()
                )
            }
            Self::SeedPermissions { mode } => write!(
                formatter,
                "registry seed file mode {mode:03o} grants group or other access"
            ),
            Self::SeedEncoding => formatter
                .write_str("registry seed file must contain exactly 64 hexadecimal characters"),
        }
    }
}

impl Error for RegistryProcessConfigError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::SeedIo { source, .. } => Some(source),
            _ => None,
        }
    }
}
