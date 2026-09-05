use omachat_ctl::{Client, DEFAULT_TIMEOUT};
use omachat_proto::ipc::ResponseOutcome;
use omachat_tui::{UiModel, parse_input};
use ratatui::{
    Terminal, TerminalOptions, Viewport,
    backend::{Backend, ClearType, CrosstermBackend},
    crossterm::{
        cursor::Show,
        event::{self, Event, KeyCode, KeyEventKind, KeyModifiers},
        execute,
        terminal::{EnterAlternateScreen, LeaveAlternateScreen, disable_raw_mode, enable_raw_mode},
    },
    layout::Rect,
};
use std::{
    env,
    ffi::OsStr,
    io::{self, IsTerminal, Stdout},
    path::PathBuf,
    process::ExitCode,
    thread,
};
use tokio::{
    io::{AsyncBufReadExt, BufReader},
    sync::mpsc,
};

/// Geometry used when stdout is not a terminal, preserving the fixed frame the
/// client has always written to a pipe.
const FALLBACK_WIDTH: u16 = 80;
const FALLBACK_HEIGHT: u16 = 24;
/// Terminal events are read on a blocking thread; this bounds the handover.
const EVENT_QUEUE: usize = 64;

type ClientTerminal = Terminal<CrosstermBackend<Stdout>>;

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
        status: "connected — /join /leave /who /block /send /join-room /leave-room /rooms /panic /detach".into(),
        ..UiModel::default()
    };
    let interactive = io::stdout().is_terminal();
    let _guard = match TerminalGuard::enter(interactive) {
        Ok(guard) => guard,
        Err(error) => {
            eprintln!("{error}");
            return ExitCode::from(4);
        }
    };
    let mut terminal = match build_terminal(interactive) {
        Ok(terminal) => terminal,
        Err(error) => {
            eprintln!("{error}");
            return ExitCode::from(4);
        }
    };
    if interactive {
        attached(&mut terminal, &mut client, &mut model).await;
    } else {
        redirected(&mut terminal, &mut client, &mut model).await;
    }
    ExitCode::SUCCESS
}

/// Attached to a terminal: the client owns the screen and the keyboard, so it
/// redraws on every event, including a resize, without waiting for a line.
async fn attached(terminal: &mut ClientTerminal, client: &mut Client, model: &mut UiModel) {
    let mut events = spawn_event_reader();
    loop {
        if draw(terminal, model).is_err() {
            return;
        }
        let Some(event) = events.recv().await else {
            return;
        };
        match event {
            // Ratatui only clears on a horizontal shrink, so a grown viewport
            // would keep whatever the smaller frame left behind.
            Event::Resize(..) => {
                if repaint(terminal).is_err() {
                    return;
                }
            }
            Event::Key(key) if key.kind == KeyEventKind::Press => {
                let control = key.modifiers.contains(KeyModifiers::CONTROL);
                match key.code {
                    // Raw mode suppresses the terminal's own interrupt, so the
                    // client has to offer the way out itself.
                    KeyCode::Char('c' | 'd') if control => return,
                    KeyCode::Char(character) => model.input.push(character),
                    KeyCode::Backspace => {
                        model.input.pop();
                    }
                    KeyCode::Esc => model.input.clear(),
                    KeyCode::Enter => {
                        let line = std::mem::take(&mut model.input);
                        if !submit(client, model, &line).await {
                            return;
                        }
                    }
                    _ => {}
                }
            }
            _ => {}
        }
    }
}

/// Redirected to a pipe or file: no keyboard and no resize, so the client keeps
/// reading whole lines and repainting a fixed frame.
async fn redirected(terminal: &mut ClientTerminal, client: &mut Client, model: &mut UiModel) {
    let mut lines = BufReader::new(tokio::io::stdin()).lines();
    loop {
        if repaint(terminal).is_err() || draw(terminal, model).is_err() {
            return;
        }
        let Ok(Some(line)) = lines.next_line().await else {
            return;
        };
        if !submit(client, model, &line).await {
            return;
        }
    }
}

/// Terminal events block a dedicated thread and reach the runtime over a
/// bounded channel, which keeps the client's only new dependency on crossterm
/// itself rather than an async event-stream stack.
fn spawn_event_reader() -> mpsc::Receiver<Event> {
    let (sender, receiver) = mpsc::channel(EVENT_QUEUE);
    thread::spawn(move || {
        while let Ok(event) = event::read() {
            if sender.blocking_send(event).is_err() {
                break;
            }
        }
    });
    receiver
}

fn draw(terminal: &mut ClientTerminal, model: &UiModel) -> io::Result<()> {
    terminal.draw(|frame| {
        let area = frame.area();
        frame.render_widget(&*model, area);
        frame.set_cursor_position(model.prompt_cursor(area));
    })?;
    Ok(())
}

/// Wipes the screen and blanks the previous buffer so the next draw is a full
/// repaint. `Terminal::clear` is unusable here because it first queries the
/// cursor position, which fails outright on a pipe.
fn repaint(terminal: &mut ClientTerminal) -> io::Result<()> {
    terminal.backend_mut().clear_region(ClearType::All)?;
    terminal.swap_buffers();
    Ok(())
}

/// Applies one composed line. Returns false when the client should detach,
/// which never stops the daemon.
async fn submit(client: &mut Client, model: &mut UiModel, line: &str) -> bool {
    if matches!(line.trim(), "/quit" | "/detach") {
        return false;
    }
    let current = model
        .conversations
        .get(model.selected)
        .map(|conversation| conversation.id.as_str());
    match parse_input(line, current) {
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
    true
}

/// A terminal drives its own geometry; a pipe keeps the fixed frame so
/// redirected output stays usable.
fn build_terminal(interactive: bool) -> io::Result<ClientTerminal> {
    let backend = CrosstermBackend::new(io::stdout());
    if interactive {
        Terminal::new(backend)
    } else {
        Terminal::with_options(
            backend,
            TerminalOptions {
                viewport: Viewport::Fixed(Rect::new(0, 0, FALLBACK_WIDTH, FALLBACK_HEIGHT)),
            },
        )
    }
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
    fn enter(active: bool) -> io::Result<Self> {
        if active {
            enable_raw_mode()?;
            if let Err(error) = execute!(io::stdout(), EnterAlternateScreen) {
                let _ = disable_raw_mode();
                return Err(error);
            }
        }
        Ok(Self { active })
    }
}

impl Drop for TerminalGuard {
    fn drop(&mut self) {
        if self.active {
            let _ = execute!(io::stdout(), Show, LeaveAlternateScreen);
            let _ = disable_raw_mode();
        }
    }
}
