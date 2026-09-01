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
                "{message}\nusage: omachat-ctl [--socket PATH] status [--json] | fingerprint [--qr] | join GEOHASH | leave GEOHASH | send CONVERSATION TEXT | discover-dm-relays PUBLIC_KEY | discover-nip65-relays PUBLIC_KEY | show-nip65-relays PUBLIC_KEY | discover-profile PUBLIC_KEY | show-profile PUBLIC_KEY | publish-profile [--json] | publish-nip65-relays [--json] | resolve-handle HANDLE [--json] | show-handle HANDLE [--json] | claim-handle HANDLE --confirm HANDLE [--json] | panic --confirm ERASE"
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
            } else if output_mode == OutputMode::Nip65Publication {
                println!("{}", format_nip65_publication(&result)?);
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
    Nip65Publication,
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
        ["discover-nip65-relays", public_key] => Ok((
            Command::DiscoverNip65Relays {
                public_key: (*public_key).into(),
            },
            OutputMode::Human,
        )),
        ["show-nip65-relays", public_key] => Ok((
            Command::ShowNip65Relays {
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
        ["publish-profile"] => Ok((Command::PublishProfile, OutputMode::Human)),
        ["publish-profile", "--json"] => Ok((Command::PublishProfile, OutputMode::Json)),
        ["publish-nip65-relays"] => Ok((Command::PublishNip65Relays, OutputMode::Nip65Publication)),
        ["publish-nip65-relays", "--json"] => Ok((Command::PublishNip65Relays, OutputMode::Json)),
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
        ["show-handle", handle] => Ok((
            Command::ShowRegistryHandle {
                handle: (*handle).into(),
            },
            OutputMode::Human,
        )),
        ["show-handle", handle, "--json"] => Ok((
            Command::ShowRegistryHandle {
                handle: (*handle).into(),
            },
            OutputMode::Json,
        )),
        ["claim-handle", handle, "--confirm", confirmation] => Ok((
            Command::ClaimRegistryHandle {
                handle: (*handle).into(),
                confirmation: (*confirmation).into(),
            },
            OutputMode::Human,
        )),
        ["claim-handle", handle, "--confirm", confirmation, "--json"] => Ok((
            Command::ClaimRegistryHandle {
                handle: (*handle).into(),
                confirmation: (*confirmation).into(),
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

fn format_nip65_publication(result: &serde_json::Value) -> Result<String, CliError> {
    let text = |field: &str| {
        result
            .get(field)
            .and_then(serde_json::Value::as_str)
            .ok_or_else(|| {
                CliError::Usage(format!(
                    "daemon returned invalid NIP-65 publication field {field}"
                ))
            })
    };
    let relays = |field: &str| {
        result
            .get(field)
            .and_then(serde_json::Value::as_array)
            .and_then(|values| {
                values
                    .iter()
                    .map(serde_json::Value::as_str)
                    .collect::<Option<Vec<_>>>()
            })
            .ok_or_else(|| {
                CliError::Usage(format!(
                    "daemon returned invalid NIP-65 publication field {field}"
                ))
            })
    };
    let required = result
        .get("required_acknowledgements")
        .and_then(serde_json::Value::as_u64)
        .ok_or_else(|| {
            CliError::Usage(
                "daemon returned invalid NIP-65 publication field required_acknowledgements".into(),
            )
        })?;
    if result
        .get("identity_verified_by_relay_list")
        .and_then(serde_json::Value::as_bool)
        != Some(false)
    {
        return Err(CliError::Usage(
            "daemon returned an unsafe NIP-65 identity-authority claim".into(),
        ));
    }
    let acknowledged = relays("acknowledged_relays")?;
    let rejected = relays("rejected_relays")?;
    let failed = relays("failed_relays")?;
    let mut lines = vec![
        format!(
            "NIP-65 publication: {} ({})",
            text("publication_status")?,
            text("publication_source")?
        ),
        format!("event: {}", text("event_id")?),
        format!("author: {}", text("public_key")?),
        format!("acknowledged: {}/{required}", acknowledged.len()),
    ];
    if !rejected.is_empty() {
        lines.push(format!("rejected: {}", rejected.join(", ")));
    }
    if !failed.is_empty() {
        lines.push(format!("failed: {}", failed.join(", ")));
    }
    lines.push("identity authority: no (NIP-65 is reachability metadata)".into());
    Ok(lines.join("\n"))
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
    fn parses_nip65_discovery_and_offline_lookup() {
        let public_key = "44".repeat(32);
        let discover = [
            std::ffi::OsString::from("discover-nip65-relays"),
            std::ffi::OsString::from(&public_key),
        ];
        let show = [
            std::ffi::OsString::from("show-nip65-relays"),
            std::ffi::OsString::from(&public_key),
        ];
        let (discover_command, discover_mode) = match parse_command(&discover) {
            Ok(parsed) => parsed,
            Err(_) => panic!("NIP-65 discovery command did not parse"),
        };
        let (show_command, show_mode) = match parse_command(&show) {
            Ok(parsed) => parsed,
            Err(_) => panic!("NIP-65 lookup command did not parse"),
        };
        assert_eq!(
            discover_command,
            Command::DiscoverNip65Relays {
                public_key: public_key.clone(),
            }
        );
        assert_eq!(show_command, Command::ShowNip65Relays { public_key });
        assert!(discover_mode == OutputMode::Human);
        assert!(show_mode == OutputMode::Human);
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
    fn parses_profile_publication_with_explicit_output_modes() {
        let human = [std::ffi::OsString::from("publish-profile")];
        let json = [
            std::ffi::OsString::from("publish-profile"),
            std::ffi::OsString::from("--json"),
        ];
        let (human_command, human_mode) = match parse_command(&human) {
            Ok(parsed) => parsed,
            Err(_) => panic!("human publication did not parse"),
        };
        let (json_command, json_mode) = match parse_command(&json) {
            Ok(parsed) => parsed,
            Err(_) => panic!("JSON publication did not parse"),
        };
        assert_eq!(human_command, Command::PublishProfile);
        assert_eq!(json_command, Command::PublishProfile);
        assert!(human_mode == OutputMode::Human);
        assert!(json_mode == OutputMode::Json);
    }

    #[test]
    fn parses_relay_list_publication_with_explicit_output_modes() {
        let human = [std::ffi::OsString::from("publish-nip65-relays")];
        let json = [
            std::ffi::OsString::from("publish-nip65-relays"),
            std::ffi::OsString::from("--json"),
        ];
        let (human_command, human_mode) = match parse_command(&human) {
            Ok(parsed) => parsed,
            Err(_) => panic!("human publication did not parse"),
        };
        let (json_command, json_mode) = match parse_command(&json) {
            Ok(parsed) => parsed,
            Err(_) => panic!("JSON publication did not parse"),
        };
        assert_eq!(human_command, Command::PublishNip65Relays);
        assert_eq!(json_command, Command::PublishNip65Relays);
        assert!(human_mode == OutputMode::Nip65Publication);
        assert!(json_mode == OutputMode::Json);
    }

    #[test]
    fn renders_relay_list_publication_without_claiming_identity_authority() {
        let result = serde_json::json!({
            "event_id": "event-id",
            "public_key": "public-key",
            "publication_status": "pending",
            "publication_source": "sealed-replay",
            "attempted_relays": ["wss://relay.one/"],
            "acknowledged_relays": ["wss://relay.one/"],
            "rejected_relays": ["wss://relay.two/"],
            "failed_relays": [],
            "required_acknowledgements": 2,
            "identity_verified_by_relay_list": false
        });
        let rendered = match format_nip65_publication(&result) {
            Ok(rendered) => rendered,
            Err(_) => panic!("publication did not render"),
        };
        assert_eq!(
            rendered,
            "NIP-65 publication: pending (sealed-replay)\nevent: event-id\nauthor: public-key\nacknowledged: 1/2\nrejected: wss://relay.two/\nidentity authority: no (NIP-65 is reachability metadata)"
        );

        let mut unsafe_result = result;
        unsafe_result["identity_verified_by_relay_list"] = true.into();
        assert!(format_nip65_publication(&unsafe_result).is_err());
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

    #[test]
    fn parses_registry_claim_only_with_explicit_confirmation() {
        let arguments = [
            std::ffi::OsString::from("claim-handle"),
            std::ffi::OsString::from("alice"),
            std::ffi::OsString::from("--confirm"),
            std::ffi::OsString::from("alice"),
            std::ffi::OsString::from("--json"),
        ];
        let (command, mode) = match parse_command(&arguments) {
            Ok(parsed) => parsed,
            Err(_) => panic!("claim command did not parse"),
        };
        assert_eq!(
            command,
            Command::ClaimRegistryHandle {
                handle: "alice".into(),
                confirmation: "alice".into(),
            }
        );
        assert!(mode == OutputMode::Json);
        assert!(
            parse_command(&[
                std::ffi::OsString::from("claim-handle"),
                std::ffi::OsString::from("alice"),
            ])
            .is_err()
        );
    }

    #[test]
    fn parses_cache_only_registry_lookup() {
        let arguments = [
            std::ffi::OsString::from("show-handle"),
            std::ffi::OsString::from("alice"),
            std::ffi::OsString::from("--json"),
        ];
        let (command, mode) = match parse_command(&arguments) {
            Ok(parsed) => parsed,
            Err(_) => panic!("cache-only lookup did not parse"),
        };
        assert_eq!(
            command,
            Command::ShowRegistryHandle {
                handle: "alice".into(),
            }
        );
        assert!(mode == OutputMode::Json);
    }
}
