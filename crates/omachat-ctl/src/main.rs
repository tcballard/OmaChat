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
                "{message}\nusage: omachat-ctl [--socket PATH] status [--json] | fingerprint [--qr] | send CONVERSATION TEXT | hosted-conversations [--json] | hosted-history CONVERSATION [--before SEQUENCE] [--limit COUNT] [--json] | hosted-mark-read CONVERSATION SEQUENCE | hosted-open-dm HANDLE [--json] | hosted-claim-handle HANDLE | hosted-resolve-handle HANDLE [--json] | hosted-create-workspace NAME | hosted-create-channel WORKSPACE_ID NAME | hosted-add-member WORKSPACE_ID HANDLE | panic --confirm ERASE"
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
    if matches!(command, Command::Panic { .. }) {
        eprintln!("{}", omachat_ctl::PANIC_ERASE_WARNING);
    }
    let response = omachat_ctl::request_with_confirmation(&mut client, command)
        .await
        .map_err(CliError::Client)?;
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
        ["send", conversation, text] => Ok((
            Command::Send {
                conversation: (*conversation).into(),
                text: (*text).into(),
            },
            OutputMode::Human,
        )),
        ["panic", "--confirm", confirmation] => Ok((
            Command::Panic {
                confirmation: (*confirmation).into(),
            },
            OutputMode::Human,
        )),
        [name, rest @ ..] if name.starts_with("hosted-") => parse_hosted_command(name, rest),
        _ => Err(CliError::Usage("invalid command".into())),
    }
}

/// Hosted server commands (ADR 0007). Every result is JSON from the daemon;
/// `--json` prints it on one line, otherwise it is pretty-printed.
fn parse_hosted_command(name: &str, rest: &[&str]) -> Result<(Command, OutputMode), CliError> {
    let (rest, mode) = match rest.split_last() {
        Some((&"--json", head)) => (head, OutputMode::Json),
        _ => (rest, OutputMode::Human),
    };
    let command = match (name, rest) {
        ("hosted-conversations", []) => Command::HostedConversations,
        ("hosted-history", [conversation, options @ ..]) => {
            let mut before_sequence = None;
            let mut limit = None;
            let mut options = options.iter();
            while let Some(option) = options.next() {
                let value = options
                    .next()
                    .ok_or_else(|| CliError::Usage(format!("{option} requires a value")))?;
                match *option {
                    "--before" => {
                        before_sequence = Some(value.parse().map_err(|_| {
                            CliError::Usage("--before requires a sequence number".into())
                        })?);
                    }
                    "--limit" => {
                        limit = Some(
                            value
                                .parse()
                                .map_err(|_| CliError::Usage("--limit requires a count".into()))?,
                        );
                    }
                    _ => return Err(CliError::Usage("invalid command".into())),
                }
            }
            Command::HostedHistory {
                conversation: (*conversation).into(),
                before_sequence,
                limit,
            }
        }
        ("hosted-mark-read", [conversation, sequence]) => Command::HostedMarkRead {
            conversation: (*conversation).into(),
            sequence: sequence
                .parse()
                .map_err(|_| CliError::Usage("SEQUENCE must be a number".into()))?,
        },
        ("hosted-open-dm", [handle]) => Command::HostedOpenDm {
            handle: (*handle).into(),
        },
        ("hosted-claim-handle", [handle]) => Command::HostedClaimHandle {
            handle: (*handle).into(),
        },
        ("hosted-resolve-handle", [handle]) => Command::HostedResolveHandle {
            handle: (*handle).into(),
        },
        ("hosted-create-workspace", [name]) => Command::HostedCreateWorkspace {
            name: (*name).into(),
        },
        ("hosted-create-channel", [workspace_id, name]) => Command::HostedCreateChannel {
            workspace_id: (*workspace_id).into(),
            name: (*name).into(),
        },
        ("hosted-add-member", [workspace_id, handle]) => Command::HostedAddMember {
            workspace_id: (*workspace_id).into(),
            handle: (*handle).into(),
        },
        _ => return Err(CliError::Usage("invalid command".into())),
    };
    Ok((command, mode))
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
    fn parses_hosted_commands() {
        let args = |parts: &[&str]| {
            parts
                .iter()
                .map(std::ffi::OsString::from)
                .collect::<Vec<_>>()
        };
        let parse = |parts: &[&str]| {
            parse_command(&args(parts)).unwrap_or_else(|_| panic!("{parts:?} did not parse"))
        };
        let (command, mode) = parse(&["hosted-conversations"]);
        assert_eq!(command, Command::HostedConversations);
        assert!(matches!(mode, OutputMode::Human));
        let (command, mode) = parse(&["hosted-conversations", "--json"]);
        assert_eq!(command, Command::HostedConversations);
        assert!(matches!(mode, OutputMode::Json));
        let (command, _) = parse(&[
            "hosted-history",
            "hosted:abc",
            "--before",
            "40",
            "--limit",
            "20",
            "--json",
        ]);
        assert_eq!(
            command,
            Command::HostedHistory {
                conversation: "hosted:abc".into(),
                before_sequence: Some(40),
                limit: Some(20),
            }
        );
        let (command, _) = parse(&["hosted-history", "hosted:abc"]);
        assert_eq!(
            command,
            Command::HostedHistory {
                conversation: "hosted:abc".into(),
                before_sequence: None,
                limit: None,
            }
        );
        let (command, _) = parse(&["hosted-mark-read", "hosted:abc", "7"]);
        assert_eq!(
            command,
            Command::HostedMarkRead {
                conversation: "hosted:abc".into(),
                sequence: 7,
            }
        );
        let (command, _) = parse(&["hosted-open-dm", "bob"]);
        assert_eq!(
            command,
            Command::HostedOpenDm {
                handle: "bob".into()
            }
        );
        let (command, _) = parse(&["hosted-claim-handle", "alice"]);
        assert_eq!(
            command,
            Command::HostedClaimHandle {
                handle: "alice".into()
            }
        );
        let (command, _) = parse(&["hosted-resolve-handle", "alice", "--json"]);
        assert_eq!(
            command,
            Command::HostedResolveHandle {
                handle: "alice".into()
            }
        );
        let (command, _) = parse(&["hosted-create-workspace", "Acme"]);
        assert_eq!(
            command,
            Command::HostedCreateWorkspace {
                name: "Acme".into()
            }
        );
        let (command, _) = parse(&["hosted-create-channel", "ws", "general"]);
        assert_eq!(
            command,
            Command::HostedCreateChannel {
                workspace_id: "ws".into(),
                name: "general".into(),
            }
        );
        let (command, _) = parse(&["hosted-add-member", "ws", "bob"]);
        assert_eq!(
            command,
            Command::HostedAddMember {
                workspace_id: "ws".into(),
                handle: "bob".into(),
            }
        );
        for invalid in [
            &["hosted-history"][..],
            &["hosted-history", "hosted:abc", "--before"],
            &["hosted-history", "hosted:abc", "--before", "x"],
            &["hosted-history", "hosted:abc", "--after", "1"],
            &["hosted-mark-read", "hosted:abc", "seven"],
            &["hosted-open-dm"],
            &["hosted-add-member", "ws"],
            &["hosted-unknown"],
        ] {
            assert!(
                parse_command(&args(invalid)).is_err(),
                "{invalid:?} must be rejected"
            );
        }
    }
}
