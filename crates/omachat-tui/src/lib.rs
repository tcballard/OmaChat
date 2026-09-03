//! Deterministic ANSI-16 terminal model and command mapping.

use omachat_proto::ipc::Command;
use ratatui::{
    buffer::Buffer,
    layout::{Constraint, Layout, Position, Rect},
    style::{Color, Modifier, Style},
    widgets::Widget,
};

/// Layouts below either bound collapse to the single-column presentation.
const NARROW_WIDTH: u16 = 30;
const NARROW_HEIGHT: u16 = 8;
/// Sidebar bounds applied to one third of the available width.
const SIDEBAR_MINIMUM: u16 = 18;
const SIDEBAR_MAXIMUM: u16 = 28;
/// Columns the `"> "` prompt occupies before composed text starts.
const PROMPT_WIDTH: u16 = 2;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DeliveryState {
    Queued,
    Stored,
    Failed,
}

impl DeliveryState {
    #[must_use]
    pub fn glyph(self) -> &'static str {
        match self {
            Self::Queued => "○",
            Self::Stored => "✓",
            Self::Failed => "!",
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Message {
    pub sender: String,
    pub text: String,
    pub outgoing: bool,
    pub delivery: Option<DeliveryState>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Conversation {
    pub id: String,
    pub title: String,
    pub unread: usize,
    pub messages: Vec<Message>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum InputMode {
    Compose,
    Scroll,
}

impl InputMode {
    #[must_use]
    pub fn label(self) -> &'static str {
        match self {
            Self::Compose => "Compose",
            Self::Scroll => "Scroll",
        }
    }
}

pub struct UiModel {
    pub conversations: Vec<Conversation>,
    pub selected: usize,
    pub input: String,
    pub input_mode: InputMode,
    pub connected: bool,
    pub status: String,
    pub security_notice_pending: bool,
}

impl Default for UiModel {
    fn default() -> Self {
        Self {
            conversations: Vec::new(),
            selected: 0,
            input: String::new(),
            input_mode: InputMode::Compose,
            connected: false,
            status: "detached".into(),
            security_notice_pending: true,
        }
    }
}

/// Every style below resolves to one of the sixteen ANSI colours, so the
/// rendered buffer never carries a truecolor or extended-palette cell.
fn heading_style() -> Style {
    Style::new().fg(Color::Cyan).add_modifier(Modifier::BOLD)
}

fn title_style() -> Style {
    Style::new().fg(Color::White).add_modifier(Modifier::BOLD)
}

fn sidebar_style() -> Style {
    Style::new().fg(Color::White)
}

fn status_style() -> Style {
    Style::new().fg(Color::Black).bg(Color::White)
}

fn prompt_style() -> Style {
    Style::new().fg(Color::Cyan)
}

impl Widget for &UiModel {
    fn render(self, area: Rect, buffer: &mut Buffer) {
        if area.width < NARROW_WIDTH || area.height < NARROW_HEIGHT {
            self.render_narrow(area, buffer);
        } else {
            self.render_wide(area, buffer);
        }
    }
}

impl UiModel {
    /// Two-column presentation: conversation sidebar, message pane, status bar,
    /// and prompt.
    fn render_wide(&self, area: Rect, buffer: &mut Buffer) {
        let [heading, body, status, prompt] = Layout::vertical([
            Constraint::Length(1),
            Constraint::Min(0),
            Constraint::Length(1),
            Constraint::Length(1),
        ])
        .areas(area);
        let sidebar_width = (area.width / 3).clamp(SIDEBAR_MINIMUM, SIDEBAR_MAXIMUM);
        let [sidebar, divider, content] = Layout::horizontal([
            Constraint::Length(sidebar_width),
            Constraint::Length(1),
            Constraint::Min(0),
        ])
        .areas(area);

        write_line(
            buffer,
            row(sidebar, heading.y),
            " Conversations",
            heading_style(),
        );
        write_line(buffer, row(divider, heading.y), "│", Style::new());
        write_line(
            buffer,
            row(content, heading.y),
            &format!(" {}", self.selected_title()),
            title_style(),
        );

        let messages = self.selected_messages();
        for offset in 0..body.height {
            let index = usize::from(offset);
            let y = body.y.saturating_add(offset);
            if let Some(conversation) = self.conversations.get(index) {
                let marker = if index == self.selected { ">" } else { " " };
                let unread = if conversation.unread == 0 {
                    String::new()
                } else {
                    format!(" ({})", conversation.unread)
                };
                write_line(
                    buffer,
                    row(sidebar, y),
                    &format!("{marker} {}{unread}", conversation.title),
                    sidebar_style(),
                );
            }
            write_line(buffer, row(divider, y), "│", Style::new());
            if let Some(message) = messages.get(index) {
                write_line(
                    buffer,
                    row(content, y),
                    &format!(" {}", render_message(message)),
                    Style::new(),
                );
            }
        }

        self.render_status(status, buffer, true);
        self.render_prompt(prompt, buffer);
    }

    /// Single-column fallback for terminals too small for the sidebar.
    fn render_narrow(&self, area: Rect, buffer: &mut Buffer) {
        let [heading, body, status, prompt] = Layout::vertical([
            Constraint::Length(1),
            Constraint::Min(0),
            Constraint::Length(1),
            Constraint::Length(1),
        ])
        .areas(area);

        write_line(buffer, heading, self.selected_title(), heading_style());
        for (offset, message) in self
            .selected_messages()
            .iter()
            .take(usize::from(body.height))
            .enumerate()
        {
            let Ok(offset) = u16::try_from(offset) else {
                break;
            };
            write_line(
                buffer,
                row(body, body.y.saturating_add(offset)),
                &render_message(message),
                Style::new(),
            );
        }

        self.render_status(status, buffer, false);
        self.render_prompt(prompt, buffer);
    }

    fn render_status(&self, area: Rect, buffer: &mut Buffer, detailed: bool) {
        if area.is_empty() {
            return;
        }
        buffer.set_style(area, status_style());
        let text = if detailed {
            format!(
                " {} | {}{}",
                self.status,
                self.input_mode.label(),
                if self.security_notice_pending {
                    " | relay DMs use mobile-compatible envelopes"
                } else {
                    ""
                }
            )
        } else {
            self.status.clone()
        };
        write_line(buffer, area, &text, status_style());
    }

    fn render_prompt(&self, area: Rect, buffer: &mut Buffer) {
        if area.is_empty() {
            return;
        }
        write_line(buffer, area, ">", prompt_style());
        let input = Rect {
            x: area.x.saturating_add(PROMPT_WIDTH),
            width: area.width.saturating_sub(PROMPT_WIDTH),
            ..area
        };
        write_line(buffer, input, &self.input, Style::new());
    }

    /// Where the caret belongs: immediately after the prompt and any text
    /// already composed. The client is still line-oriented, so the terminal
    /// echoes typed characters at the caret and they must land on the prompt
    /// row rather than wherever the last buffer diff happened to end.
    #[must_use]
    pub fn prompt_cursor(&self, area: Rect) -> Position {
        if area.is_empty() {
            return Position::new(area.x, area.y);
        }
        let composed = u16::try_from(self.input.chars().count()).unwrap_or(u16::MAX);
        let x = area
            .x
            .saturating_add(PROMPT_WIDTH)
            .saturating_add(composed)
            .min(area.right().saturating_sub(1));
        Position::new(x, area.bottom().saturating_sub(1))
    }

    fn selected_title(&self) -> &str {
        self.conversations
            .get(self.selected)
            .map_or("No conversation", |conversation| {
                conversation.title.as_str()
            })
    }

    fn selected_messages(&self) -> &[Message] {
        self.conversations
            .get(self.selected)
            .map_or(&[], |conversation| conversation.messages.as_slice())
    }
}

/// One row of `area` at absolute row `y`, empty when `y` falls outside.
fn row(area: Rect, y: u16) -> Rect {
    if area.height == 0 || y < area.y || y >= area.bottom() {
        return Rect::new(area.x, area.y, area.width, 0);
    }
    Rect {
        y,
        height: 1,
        ..area
    }
}

/// Writes `text` clipped to `area`, which may legitimately be empty when the
/// terminal is smaller than the layout wants.
fn write_line(buffer: &mut Buffer, area: Rect, text: &str, style: Style) {
    if area.is_empty() {
        return;
    }
    buffer.set_stringn(area.x, area.y, text, usize::from(area.width), style);
}

fn render_message(message: &Message) -> String {
    let delivery = message.delivery.map_or("", DeliveryState::glyph);
    if message.outgoing {
        format!("you: {} {delivery}", message.text)
    } else {
        format!("{}: {}", message.sender, message.text)
    }
}

pub fn parse_input(
    input: &str,
    current_conversation: Option<&str>,
) -> Result<Option<Command>, String> {
    let input = input.trim();
    if input.is_empty() {
        return Ok(None);
    }
    if let Some(arguments) = input.strip_prefix('/') {
        let mut parts = arguments.splitn(3, ' ');
        return match (parts.next(), parts.next(), parts.next()) {
            (Some("join"), Some(geohash), None) => Ok(Some(Command::Join {
                geohash: geohash.into(),
            })),
            (Some("leave"), Some(geohash), None) => Ok(Some(Command::Leave {
                geohash: geohash.into(),
            })),
            (Some("who"), Some(geohash), None) => Ok(Some(Command::Who {
                geohash: geohash.into(),
            })),
            (Some("block"), Some(public_key), None) => Ok(Some(Command::Block {
                public_key: public_key.into(),
            })),
            (Some("panic"), Some(confirmation), None) => Ok(Some(Command::Panic {
                confirmation: confirmation.into(),
            })),
            (Some("send"), Some(conversation), Some(text)) => Ok(Some(Command::Send {
                conversation: conversation.into(),
                text: text.into(),
            })),
            (Some("join-room"), Some(relay), Some(rest)) => {
                let mut parts = rest.split_whitespace();
                let group_id = parts.next().ok_or("join-room needs RELAY GROUP [CODE]")?;
                let invite_code = parts.next().map(str::to_owned);
                if parts.next().is_some() {
                    return Err("join-room needs RELAY GROUP [CODE]".into());
                }
                Ok(Some(Command::JoinRoom {
                    relay: relay.into(),
                    group_id: group_id.into(),
                    invite_code,
                }))
            }
            (Some("leave-room"), Some(relay), Some(group_id)) if !group_id.contains(' ') => {
                Ok(Some(Command::LeaveRoom {
                    relay: relay.into(),
                    group_id: group_id.into(),
                }))
            }
            (Some("rooms"), None, None) => Ok(Some(Command::ListRooms)),
            (Some("quit" | "detach"), None, None) => Ok(None),
            _ => Err("unknown or incomplete command".into()),
        };
    }
    let conversation = current_conversation.ok_or("select a conversation before sending")?;
    Ok(Some(Command::Send {
        conversation: conversation.into(),
        text: input.into(),
    }))
}

#[cfg(test)]
mod room_command_tests {
    use super::*;

    #[test]
    fn room_slash_commands_parse() {
        assert_eq!(
            parse_input("/join-room wss://r.example omarchy", None),
            Ok(Some(Command::JoinRoom {
                relay: "wss://r.example".into(),
                group_id: "omarchy".into(),
                invite_code: None,
            }))
        );
        assert_eq!(
            parse_input("/join-room wss://r.example omarchy welcome", None),
            Ok(Some(Command::JoinRoom {
                relay: "wss://r.example".into(),
                group_id: "omarchy".into(),
                invite_code: Some("welcome".into()),
            }))
        );
        assert!(parse_input("/join-room wss://r.example omarchy a b", None).is_err());
        assert_eq!(
            parse_input("/leave-room wss://r.example omarchy", None),
            Ok(Some(Command::LeaveRoom {
                relay: "wss://r.example".into(),
                group_id: "omarchy".into(),
            }))
        );
        assert_eq!(parse_input("/rooms", None), Ok(Some(Command::ListRooms)));
        assert_eq!(
            parse_input("hello", Some("room:aa:omarchy")),
            Ok(Some(Command::Send {
                conversation: "room:aa:omarchy".into(),
                text: "hello".into(),
            }))
        );
    }
}
