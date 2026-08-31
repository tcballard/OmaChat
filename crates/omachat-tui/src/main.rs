use omachat_ctl::{Client, DEFAULT_TIMEOUT};
use omachat_proto::ipc::ResponseOutcome;
use omachat_tui::{UiModel, parse_input};
use std::{
    env,
    ffi::OsStr,
    io::{self, IsTerminal, Write},
    path::PathBuf,
    process::ExitCode,
};
use tokio::io::{AsyncBufReadExt, BufReader};

#[tokio::main]
async fn main() -> ExitCode {
    let arguments = env::args_os().skip(1).collect::<Vec<_>>();
    if arguments.as_slice() == [OsStr::new("--version")] {
        println!("{}", omachat_proto::version_line("omachat"));
        return ExitCode::SUCCESS;
    }
    let socket = match socket_path(&arguments) {
        Ok(path) => path,
        Err(message) => {
            eprintln!("{message}");
            return ExitCode::from(2);
        }
    };
    let mut client = match Client::connect(socket, DEFAULT_TIMEOUT).await {
        Ok(client) => client,
        Err(error) => {
            eprintln!("{error}");
            return ExitCode::from(3);
        }
    };
    let mut model = UiModel {
        connected: true,
        status: "connected — /join /leave /who /block /send /panic /detach".into(),
        ..UiModel::default()
    };
    let _terminal = TerminalGuard::enter();
    let mut input = BufReader::new(tokio::io::stdin()).lines();
    loop {
        print!("\x1b[H\x1b[2J{}", model.render(80, 24));
        let _ = io::stdout().flush();
        let Ok(Some(line)) = input.next_line().await else {
            break;
        };
        if matches!(line.trim(), "/quit" | "/detach") {
            break;
        }
        let current = model
            .conversations
            .get(model.selected)
            .map(|conversation| conversation.id.as_str());
        match parse_input(&line, current) {
            Ok(Some(command)) => match client.request(command).await {
                Ok(response) => match response.outcome {
                    ResponseOutcome::Ok { result } => {
                        model.status = result.to_string();
                        model.security_notice_pending = false;
                    }
                    ResponseOutcome::Error { error } => model.status = error.message,
                },
                Err(error) => model.status = format!("disconnected: {error}"),
            },
            Ok(None) => {}
            Err(error) => model.status = error,
        }
    }
    ExitCode::SUCCESS
}

fn socket_path(arguments: &[std::ffi::OsString]) -> Result<PathBuf, String> {
    match arguments {
        [] => env::var_os("XDG_RUNTIME_DIR")
            .map(PathBuf::from)
            .map(|path| path.join("omachat/omachat.sock"))
            .ok_or_else(|| "XDG_RUNTIME_DIR is not set; pass --socket PATH".into()),
        [flag, path] if flag == "--socket" => Ok(PathBuf::from(path)),
        _ => Err("usage: omachat [--socket PATH]".into()),
    }
}

struct TerminalGuard {
    active: bool,
}

impl TerminalGuard {
    fn enter() -> Self {
        let active = io::stdout().is_terminal();
        if active {
            print!("\x1b[?1049h\x1b[?25l");
            let _ = io::stdout().flush();
        }
        Self { active }
    }
}

impl Drop for TerminalGuard {
    fn drop(&mut self) {
        if self.active {
            print!("\x1b[0m\x1b[?25h\x1b[?1049l");
            let _ = io::stdout().flush();
        }
    }
}
