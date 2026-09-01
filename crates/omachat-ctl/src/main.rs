use omachat_ctl::{Client, ClientError, DEFAULT_TIMEOUT};
use omachat_proto::ipc::{Command, ResponseOutcome};
use std::{env, ffi::OsStr, path::PathBuf, process::ExitCode};

#[tokio::main]
async fn main() -> ExitCode {
    let arguments = env::args_os().skip(1).collect::<Vec<_>>();
    if arguments.as_slice() == [OsStr::new("--version")] {
        println!("{}", omachat_proto::version_line("omachat-ctl"));
        return ExitCode::SUCCESS;
    }
    match run(arguments).await {
        Ok(()) => ExitCode::SUCCESS,
        Err(CliError::Usage(message)) => {
            eprintln!(
                "{message}\nusage: omachat-ctl [--socket PATH] status [--json] | fingerprint [--qr] | join GEOHASH | leave GEOHASH | send CONVERSATION TEXT | discover-dm-relays PUBLIC_KEY | discover-profile PUBLIC_KEY | show-profile PUBLIC_KEY | resolve-handle HANDLE [--json] | panic --confirm ERASE"
            );
            ExitCode::from(2)
        }
        Err(CliError::Client(error)) => {
            eprintln!("{error}");
            match error {
                ClientError::VersionMismatch(_) | ClientError::Remote { .. } => ExitCode::from(4),
                ClientError::Timeout => ExitCode::from(5),
                _ => ExitCode::from(3),
            }
        }
    }
}

async fn run(mut arguments: Vec<std::ffi::OsString>) -> Result<(), CliError> {
    let socket = if arguments.first().is_some_and(|value| value == "--socket") {
        if arguments.len() < 2 {
            return Err(CliError::Usage("--socket requires a path".into()));
        }
        let path = PathBuf::from(arguments.remove(1));
        arguments.remove(0);
        path
    } else {
        default_socket()?
    };
    let (command, output_mode) = parse_command(&arguments)?;
    let mut client = Client::connect(socket, DEFAULT_TIMEOUT)
        .await
        .map_err(CliError::Client)?;
    let response = client.request(command).await.map_err(CliError::Client)?;
    match response.outcome {
        ResponseOutcome::Ok { result } => {
            if output_mode == OutputMode::Json {
                println!(
                    "{}",
                    serde_json::to_string(&result).expect("JSON value serializes")
                );
            } else if output_mode == OutputMode::Qr {
                let fingerprint = result.as_str().ok_or_else(|| {
                    CliError::Usage("daemon returned a non-text fingerprint".into())
                })?;
                let status = std::process::Command::new("qrencode")
                    .args(["-t", "ANSIUTF8", fingerprint])
                    .status()
                    .map_err(|_| CliError::Usage("qrencode is required for --qr output".into()))?;
                if !status.success() {
                    return Err(CliError::Usage("qrencode failed".into()));
                }
            } else if let Some(value) = result.as_str() {
                println!("{value}");
            } else {
                println!(
                    "{}",
                    serde_json::to_string_pretty(&result).expect("JSON value serializes")
                );
            }
            Ok(())
        }
        ResponseOutcome::Error { error } => Err(CliError::Client(ClientError::Remote {
            code: format!("{:?}", error.code),
            message: error.message,
        })),
    }
}

#[derive(Clone, Copy, Eq, PartialEq)]
enum OutputMode {
    Human,
    Json,
    Qr,
}

fn parse_command(arguments: &[std::ffi::OsString]) -> Result<(Command, OutputMode), CliError> {
    let strings = arguments
        .iter()
        .map(|value| {
            value
                .to_str()
                .ok_or_else(|| CliError::Usage("arguments must be UTF-8".into()))
        })
        .collect::<Result<Vec<_>, _>>()?;
    match strings.as_slice() {
        ["status"] => Ok((Command::Status, OutputMode::Human)),
        ["status", "--json"] => Ok((Command::Status, OutputMode::Json)),
        ["fingerprint"] => Ok((Command::Fingerprint, OutputMode::Human)),
        ["fingerprint", "--qr"] => Ok((Command::Fingerprint, OutputMode::Qr)),
        ["join", geohash] => Ok((
            Command::Join {
                geohash: (*geohash).into(),
            },
            OutputMode::Human,
        )),
        ["leave", geohash] => Ok((
            Command::Leave {
                geohash: (*geohash).into(),
            },
            OutputMode::Human,
        )),
        ["send", conversation, text] => Ok((
            Command::Send {
                conversation: (*conversation).into(),
                text: (*text).into(),
            },
            OutputMode::Human,
        )),
        ["discover-dm-relays", public_key] => Ok((
            Command::DiscoverDmRelays {
                public_key: (*public_key).into(),
            },
            OutputMode::Human,
        )),
        ["discover-profile", public_key] => Ok((
            Command::DiscoverProfile {
                public_key: (*public_key).into(),
            },
            OutputMode::Human,
        )),
        ["show-profile", public_key] => Ok((
            Command::ShowProfile {
                public_key: (*public_key).into(),
            },
            OutputMode::Human,
        )),
        ["resolve-handle", handle] => Ok((
            Command::ResolveRegistryHandle {
                handle: (*handle).into(),
            },
            OutputMode::Human,
        )),
        ["resolve-handle", handle, "--json"] => Ok((
            Command::ResolveRegistryHandle {
                handle: (*handle).into(),
            },
            OutputMode::Json,
        )),
        ["panic", "--confirm", confirmation] => Ok((
            Command::Panic {
                confirmation: (*confirmation).into(),
            },
            OutputMode::Human,
        )),
        _ => Err(CliError::Usage("invalid command".into())),
    }
}

fn default_socket() -> Result<PathBuf, CliError> {
    let runtime = env::var_os("XDG_RUNTIME_DIR")
        .ok_or_else(|| CliError::Usage("XDG_RUNTIME_DIR is not set; pass --socket".into()))?;
    Ok(PathBuf::from(runtime).join("omachat/omachat.sock"))
}

enum CliError {
    Usage(String),
    Client(ClientError),
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_explicit_dm_relay_discovery() {
        let arguments = [
            std::ffi::OsString::from("discover-dm-relays"),
            std::ffi::OsString::from("11".repeat(32)),
        ];
        let (command, mode) = match parse_command(&arguments) {
            Ok(parsed) => parsed,
            Err(_) => panic!("discovery command did not parse"),
        };
        assert!(mode == OutputMode::Human);
        assert_eq!(
            command,
            Command::DiscoverDmRelays {
                public_key: "11".repeat(32),
            }
        );
    }

    #[test]
    fn parses_explicit_profile_discovery() {
        let arguments = [
            std::ffi::OsString::from("discover-profile"),
            std::ffi::OsString::from("22".repeat(32)),
        ];
        let (command, mode) = match parse_command(&arguments) {
            Ok(parsed) => parsed,
            Err(_) => panic!("profile discovery command did not parse"),
        };
        assert!(mode == OutputMode::Human);
        assert_eq!(
            command,
            Command::DiscoverProfile {
                public_key: "22".repeat(32),
            }
        );
    }

    #[test]
    fn parses_offline_profile_lookup() {
        let arguments = [
            std::ffi::OsString::from("show-profile"),
            std::ffi::OsString::from("33".repeat(32)),
        ];
        let (command, mode) = match parse_command(&arguments) {
            Ok(parsed) => parsed,
            Err(_) => panic!("profile lookup command did not parse"),
        };
        assert!(mode == OutputMode::Human);
        assert_eq!(
            command,
            Command::ShowProfile {
                public_key: "33".repeat(32),
            }
        );
    }

    #[test]
    fn parses_verified_registry_resolution_with_explicit_output_modes() {
        let human = [
            std::ffi::OsString::from("resolve-handle"),
            std::ffi::OsString::from("alice"),
        ];
        let json = [
            std::ffi::OsString::from("resolve-handle"),
            std::ffi::OsString::from("alice"),
            std::ffi::OsString::from("--json"),
        ];
        let (human_command, human_mode) = match parse_command(&human) {
            Ok(parsed) => parsed,
            Err(_) => panic!("human command did not parse"),
        };
        let (json_command, json_mode) = match parse_command(&json) {
            Ok(parsed) => parsed,
            Err(_) => panic!("JSON command did not parse"),
        };
        let expected = Command::ResolveRegistryHandle {
            handle: "alice".into(),
        };
        assert_eq!(human_command, expected);
        assert_eq!(json_command, expected);
        assert!(human_mode == OutputMode::Human);
        assert!(json_mode == OutputMode::Json);
    }
}
