use omachat_ctl::{Client, DEFAULT_TIMEOUT};
use omachat_proto::ipc::{Command, ResponseOutcome, Topic};
use omachat_tui::{InputMode, UiModel, parse_input};
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
    sync::atomic::{AtomicBool, Ordering},
    thread,
    time::Duration,
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
    let mut model = UiModel::default();
    let mut terminate =
        match tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate()) {
            Ok(signal) => signal,
            Err(error) => {
                eprintln!("{error}");
                return ExitCode::from(4);
            }
        };
    let mut interrupt =
        match tokio::signal::unix::signal(tokio::signal::unix::SignalKind::interrupt()) {
            Ok(signal) => signal,
            Err(error) => {
                eprintln!("{error}");
                return ExitCode::from(4);
            }
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
    tokio::select! {
        _ = terminate.recv() => {},
        _ = interrupt.recv() => {},
        _ = attached(&mut terminal, &socket, &mut model, interactive) => {},
    }
    ExitCode::SUCCESS
}

async fn attached(
    terminal: &mut ClientTerminal,
    socket: &std::path::Path,
    model: &mut UiModel,
    interactive: bool,
) {
    let mut keyboard = spawn_event_reader(interactive);
    let mut client: Option<Client> = None;
    let mut daemon_events: Option<mpsc::Receiver<omachat_proto::ipc::Event>> = None;
    let mut retry = tokio::time::interval(Duration::from_secs(1));
    retry.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    let mut retry_at = tokio::time::Instant::now();
    let mut backoff = Duration::from_secs(1);
    loop {
        if !model.connected && client.is_some() {
            client = None;
            daemon_events = None;
            retry_at = tokio::time::Instant::now();
        }
        if draw(terminal, model).is_err() {
            return;
        }
        tokio::select! {
            _ = retry.tick() => {
                if client.is_none() && tokio::time::Instant::now() >= retry_at {
                    match connect(socket).await {
                        Ok((connected, snapshot, events)) => {
                            model.apply_snapshot(&snapshot);
                            client = Some(connected);
                            daemon_events = Some(events);
                            backoff = Duration::from_secs(1);
                        }
                        Err(error) => {
                            model.status = format!("reconnecting: {error}");
                            retry_at = tokio::time::Instant::now() + backoff;
                            backoff = (backoff * 2).min(Duration::from_secs(30));
                        }
                    }
                }
            }
            event = async { daemon_events.as_mut().expect("connected receiver").recv().await }, if daemon_events.is_some() => {
                if let Some(event) = event { model.apply_event(&event); }
                else {
                    client = None;
                    daemon_events = None;
                    model.connected = false;
                    model.status = "disconnected; reconnecting".into();
                    retry_at = tokio::time::Instant::now();
                }
            }
            event = keyboard.recv() => {
                let Some(event) = event else { return; };
                match event {
                    Input::Line(line) => {
                        if !handle_line(&mut client, model, &line).await { return; }
                    }
                    Input::Terminal(Event::Resize(..)) => {
                        if repaint(terminal).is_err() { return; }
                    }
                    Input::Terminal(Event::Key(key)) if key.kind == KeyEventKind::Press => {
                        let control = key.modifiers.contains(KeyModifiers::CONTROL);
                        match key.code {
                            KeyCode::Char('c' | 'd') if control => return,
                            KeyCode::Tab => model.select_next(false),
                            KeyCode::BackTab => model.select_next(true),
                            KeyCode::Esc => {
                                model.input_mode = if model.input_mode == InputMode::Compose { InputMode::Scroll } else { InputMode::Compose };
                            }
                            KeyCode::PageUp => model.scroll(true, 10),
                            KeyCode::PageDown => model.scroll(false, 10),
                            KeyCode::Up if model.input_mode == InputMode::Scroll => model.scroll(true, 1),
                            KeyCode::Down if model.input_mode == InputMode::Scroll => model.scroll(false, 1),
                            KeyCode::Char('i') if model.input_mode == InputMode::Scroll => model.input_mode = InputMode::Compose,
                            KeyCode::Char(character) if model.input_mode == InputMode::Compose && !control && model.input.len() + character.len_utf8() <= 4096 => model.input.push(character),
                            KeyCode::Backspace if model.input_mode == InputMode::Compose => { model.input.pop(); }
                            KeyCode::Enter if model.input_mode == InputMode::Compose => {
                                let line = model.input.clone();
                                if !handle_line(&mut client, model, &line).await { return; }
                            }
                            _ => {}
                        }
                    }
                    _ => {}
                }
            }
        }
    }
}

async fn connect(
    socket: &std::path::Path,
) -> Result<
    (
        Client,
        serde_json::Value,
        mpsc::Receiver<omachat_proto::ipc::Event>,
    ),
    omachat_ctl::ClientError,
> {
    let mut client = Client::connect(socket, DEFAULT_TIMEOUT).await?;
    let (snapshot, events) = client
        .subscribe(vec![
            Topic::Status,
            Topic::Conversations,
            Topic::Messages,
            Topic::Presence,
            Topic::Delivery,
        ])
        .await?;
    Ok((client, snapshot, events))
}

async fn handle_line(client: &mut Option<Client>, model: &mut UiModel, line: &str) -> bool {
    if matches!(line.trim(), "/quit" | "/detach") {
        return false;
    }
    if line.trim() == "/help" {
        model.status = "Tab/Shift-Tab: chat | Esc/i: scroll/compose | PgUp/PgDn | /join HASH | /send dm:KEY TEXT | /detach".into();
        model.input.clear();
        return true;
    }
    if let Some(client) = client.as_mut() {
        submit(client, model, line).await
    } else {
        model.status = "disconnected; draft kept, waiting to reconnect".into();
        true
    }
}

enum Input {
    Terminal(Event),
    Line(String),
}

/// Terminal events block a dedicated thread and reach the runtime over a
/// bounded channel, which keeps the client's only new dependency on crossterm
/// itself rather than an async event-stream stack.
fn spawn_event_reader(interactive: bool) -> mpsc::Receiver<Input> {
    let (sender, receiver) = mpsc::channel(EVENT_QUEUE);
    if interactive {
        thread::spawn(move || {
            while !sender.is_closed() {
                match event::poll(Duration::from_millis(100)) {
                    Ok(true) => match event::read() {
                        Ok(event) => {
                            if sender.blocking_send(Input::Terminal(event)).is_err() {
                                break;
                            }
                        }
                        Err(_) => break,
                    },
                    Ok(false) => {}
                    Err(_) => break,
                }
            }
        });
    } else {
        tokio::spawn(async move {
            let mut lines = BufReader::new(tokio::io::stdin()).lines();
            while let Ok(Some(line)) = lines.next_line().await {
                if sender.send(Input::Line(line)).await.is_err() {
                    break;
                }
            }
        });
    }
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
        Ok(Some(Command::Panic { .. })) if !model.panic_confirmation_pending => {
            model.status =
                "Panic erases local keys/history only. Repeat /panic ERASE to proceed.".into();
            model.panic_confirmation_pending = true;
        }
        Ok(Some(command)) => match omachat_ctl::request_with_confirmation(client, command).await {
            Ok(response) => match response.outcome {
                ResponseOutcome::Ok { result } => {
                    if result["erased"] == true {
                        model.conversations.clear();
                        model.selected = 0;
                        model.scroll_offset = 0;
                    }
                    model.panic_confirmation_pending = false;
                    model.input.clear();
                    model.status = result.to_string();
                    model.security_notice_pending = false;
                }
                ResponseOutcome::Error { error } => model.status = error.message,
            },
            Err(error) => {
                model.connected = false;
                model.status =
                    format!("request failed (draft kept; delivery may be unknown): {error}");
            }
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
            let previous = std::panic::take_hook();
            std::panic::set_hook(Box::new(move |info| {
                restore_terminal();
                previous(info);
            }));
            enable_raw_mode()?;
            TERMINAL_ACTIVE.store(true, Ordering::SeqCst);
            if let Err(error) = execute!(io::stdout(), EnterAlternateScreen) {
                restore_terminal();
                return Err(error);
            }
        }
        Ok(Self { active })
    }
}

impl Drop for TerminalGuard {
    fn drop(&mut self) {
        if self.active {
            restore_terminal();
        }
    }
}

static TERMINAL_ACTIVE: AtomicBool = AtomicBool::new(false);
fn restore_terminal() {
    if TERMINAL_ACTIVE.swap(false, Ordering::SeqCst) {
        let _ = execute!(io::stdout(), Show, LeaveAlternateScreen);
        let _ = disable_raw_mode();
    }
}
