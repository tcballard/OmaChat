//! `omachat` terminal client.
//!
//! Connecting calls `chat-prepare`, which seals a `nostr-identity-v1` key when
//! one is not already stored. The secret is never printed here; use
//! `omachat-ctl identity export` for the nsec.

use omachat_ctl::{Client, DEFAULT_TIMEOUT};
use omachat_proto::ipc::{ResponseOutcome, Topic};
use omachat_tui::{Action, HELP, UiModel, parse_input};
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

const FALLBACK_WIDTH: u16 = 80;
const FALLBACK_HEIGHT: u16 = 24;
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
    loop {
        if draw(terminal, model).is_err() {
            return;
        }
        tokio::select! {
            _ = retry.tick() => {
                if client.is_none() && tokio::time::Instant::now() >= retry_at {
                    match connect(socket).await {
                        Ok((mut connected, snapshot, events)) => {
                            model.apply_snapshot(&snapshot);
                            if let Ok(response) = connected.request(omachat_proto::ipc::Command::ChatPrepare).await
                                && let ResponseOutcome::Ok { result } = response.outcome
                                && let Some(npub) = result["npub"].as_str()
                            {
                                model.npub = npub.to_owned();
                                model.status = format!("npub {npub} | /help");
                            }
                            client = Some(connected);
                            daemon_events = Some(events);
                        }
                        Err(error) => {
                            model.status = format!("reconnecting: {error}");
                            retry_at = tokio::time::Instant::now() + Duration::from_secs(2);
                        }
                    }
                }
            }
            event = async { daemon_events.as_mut().expect("connected").recv().await }, if daemon_events.is_some() => {
                if let Some(event) = event {
                    model.apply_event(&event);
                } else {
                    client = None;
                    daemon_events = None;
                    model.connected = false;
                    model.status = "disconnected; reconnecting".into();
                    retry_at = tokio::time::Instant::now();
                }
            }
            event = keyboard.recv() => {
                let Some(event) = event else { return };
                match event {
                    Input::Line(line) => {
                        if !handle_line(&mut client, model, &line).await { return; }
                    }
                    Input::Terminal(Event::Key(key)) if key.kind == KeyEventKind::Press => {
                        let control = key.modifiers.contains(KeyModifiers::CONTROL);
                        match key.code {
                            KeyCode::Char('c' | 'd') if control => return,
                            KeyCode::Tab => model.select_next(false),
                            KeyCode::BackTab => model.select_next(true),
                            KeyCode::Char(character) if !control && model.input.len() + character.len_utf8() <= 4096 => {
                                model.input.push(character);
                            }
                            KeyCode::Backspace => { model.input.pop(); }
                            KeyCode::Enter => {
                                let line = model.input.clone();
                                if !handle_line(&mut client, model, &line).await { return; }
                            }
                            _ => {}
                        }
                    }
                    Input::Terminal(Event::Resize(..)) if repaint(terminal).is_err() => return,
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
    client.set_timeout(Duration::from_secs(30));
    let (snapshot, events) = client
        .subscribe(vec![
            Topic::Status,
            Topic::Conversations,
            Topic::Messages,
            Topic::Delivery,
        ])
        .await?;
    Ok((client, snapshot, events))
}

async fn handle_line(client: &mut Option<Client>, model: &mut UiModel, line: &str) -> bool {
    let mut accepted = false;
    match parse_input(line, model.selected_peer()) {
        Ok(Some(Action::Quit)) => return false,
        Ok(Some(Action::Help)) => {
            model.status = HELP.into();
            accepted = true;
        }
        Ok(Some(Action::Select(peer))) => {
            if let Some(index) = model.contacts.iter().position(|contact| {
                contact.peer == peer || contact.title == peer || contact.peer.ends_with(&peer)
            }) {
                model.selected = index;
                accepted = true;
                model.status = format!("selected {}", model.contacts[index].title);
            } else {
                model.status = "no matching contact".into();
            }
        }
        Ok(Some(Action::Command(command))) => {
            if client.is_none() {
                model.status = "disconnected; waiting to reconnect".into();
                return true;
            }
            let outcome = omachat_ctl::request_with_confirmation(
                client.as_mut().expect("checked client"),
                command,
            )
            .await;
            match outcome {
                Ok(response) => match response.outcome {
                    ResponseOutcome::Ok { result } => {
                        accepted = true;
                        if let Some(npub) = result["npub"].as_str() {
                            model.npub = npub.to_owned();
                        }
                        if let Some(relays) = result["relays"].as_array() {
                            model.relays = relays
                                .iter()
                                .filter_map(|relay| relay.as_str().map(str::to_owned))
                                .collect();
                        }
                        model.status = summarize(&result);
                    }
                    ResponseOutcome::Error { error } => model.status = error.message,
                },
                Err(error) => {
                    model.connected = false;
                    model.status = format!("request failed: {error}");
                    *client = None;
                }
            }
        }
        Ok(None) => {}
        Err(error) => model.status = error,
    }
    if accepted && model.input == line {
        model.input.clear();
    }
    true
}

fn summarize(result: &serde_json::Value) -> String {
    if let Some(npub) = result["npub"].as_str() {
        return format!("npub {npub}");
    }
    if let Some(text) = result["message"]["text"].as_str() {
        return format!("accepted by relay: {text}");
    }
    if result["contacts"].is_array() {
        return format!(
            "{} contacts",
            result["contacts"].as_array().map_or(0, Vec::len)
        );
    }
    result.to_string()
}

enum Input {
    Terminal(Event),
    Line(String),
}

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
        frame.render_widget(model, frame.area());
    })?;
    Ok(())
}

fn repaint(terminal: &mut ClientTerminal) -> io::Result<()> {
    terminal.backend_mut().clear_region(ClearType::All)?;
    terminal.swap_buffers();
    Ok(())
}

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

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn rejected_or_disconnected_input_keeps_the_draft() {
        let mut model = UiModel::default();
        let mut client = None;
        model.input = "keep this message".into();
        model.apply_snapshot(&serde_json::json!({
            "contacts": [{"pubkey": "aa", "display": "Alice"}],
            "messages": []
        }));
        assert!(handle_line(&mut client, &mut model, "keep this message").await);
        assert_eq!(model.input, "keep this message");
        model.input = "/unknown".into();
        assert!(handle_line(&mut client, &mut model, "/unknown").await);
        assert_eq!(model.input, "/unknown");
        model.input = "/help".into();
        assert!(handle_line(&mut client, &mut model, "/help").await);
        assert!(model.input.is_empty());
    }
}
