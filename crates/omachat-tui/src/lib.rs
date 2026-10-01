//! Deterministic ANSI-16 terminal model and command mapping.

use omachat_proto::ipc::{Command, Event, Topic};
use ratatui::{
    buffer::Buffer,
    layout::{Constraint, Layout, Position, Rect},
    style::{Color, Modifier, Style},
    widgets::Widget,
};
use serde_json::Value;

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
    pub id: String,
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
    pub scroll_offset: usize,
    pub input: String,
    pub input_mode: InputMode,
    pub connected: bool,
    pub status: String,
    pub security_notice_pending: bool,
    pub panic_confirmation_pending: bool,
}

impl Default for UiModel {
    fn default() -> Self {
        Self {
            conversations: Vec::new(),
            selected: 0,
            scroll_offset: 0,
            input: String::new(),
            input_mode: InputMode::Compose,
            connected: false,
            status: "detached".into(),
            security_notice_pending: true,
            panic_confirmation_pending: false,
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
    /// Replace cached messages with the daemon snapshot while retaining the draft.
    pub fn apply_snapshot(&mut self, snapshot: &Value) {
        let selected = self.conversations.get(self.selected).map(|c| c.id.clone());
        self.conversations.clear();
        self.selected = 0;
        self.scroll_offset = 0;
        if let Some(status) = snapshot.get("status") {
            self.apply_status(status);
        }
        if let Some(messages) = snapshot["messages"].as_array() {
            for message in messages {
                self.apply_message(message);
            }
        }
        if let Some(index) = self
            .conversations
            .iter()
            .position(|c| Some(&c.id) == selected.as_ref())
        {
            self.selected = index;
        }
        for conversation in &mut self.conversations {
            conversation.unread = 0;
        }
        self.connected = true;
        self.status = "connected | Tab: conversations | Esc: scroll | /help".into();
    }

    pub fn apply_event(&mut self, event: &Event) {
        match event.topic {
            Topic::Messages | Topic::Delivery => self.apply_message(&event.payload),
            Topic::Status => self.apply_status(&event.payload),
            Topic::Conversations => {
                if let Some(id) = event.payload["conversation"].as_str() {
                    let index = self.ensure_conversation(id);
                    if let Some(title) = event.payload["name"].as_str() {
                        self.conversations[index].title = clean(title);
                    }
                }
            }
            Topic::Presence => {
                self.status = format!(
                    "presence: {}",
                    clean(event.payload["conversation"].as_str().unwrap_or("peer"))
                );
            }
        }
    }

    fn apply_status(&mut self, status: &Value) {
        if let Some(joined) = status["joined_geohashes"].as_array() {
            for geohash in joined.iter().filter_map(Value::as_str) {
                self.ensure_conversation(&format!("#{geohash}"));
            }
        }
    }

    fn ensure_conversation(&mut self, id: &str) -> usize {
        if let Some(index) = self.conversations.iter().position(|c| c.id == id) {
            return index;
        }
        if self.conversations.len() == 128 {
            self.conversations.remove(0);
            self.selected = self.selected.saturating_sub(1);
        }
        self.conversations.push(Conversation {
            id: id.into(),
            title: clean(id),
            unread: 0,
            messages: Vec::new(),
        });
        self.conversations.len() - 1
    }

    fn apply_message(&mut self, payload: &Value) {
        let Some(id) = payload["id"].as_str() else {
            return;
        };
        for conversation in &mut self.conversations {
            if let Some(index) = conversation.messages.iter().position(|m| m.id == id) {
                if payload["deleted"] == true {
                    conversation.messages.remove(index);
                } else {
                    if let Some(delivery) = delivery(payload) {
                        conversation.messages[index].delivery = Some(delivery);
                    }
                    if payload["outgoing"] == true {
                        conversation.messages[index].outgoing = true;
                        conversation.messages[index].sender = "you".into();
                    }
                }
                return;
            }
        }
        let (Some(conversation), Some(text)) =
            (payload["conversation"].as_str(), payload["text"].as_str())
        else {
            return;
        };
        if payload["deleted"] == true {
            return;
        }
        let index = self.ensure_conversation(conversation);
        let outgoing = payload["outgoing"].as_bool().unwrap_or_else(|| {
            payload["delivery"]
                .as_str()
                .is_some_and(|d| d != "received")
        });
        let conversation = &mut self.conversations[index];
        if conversation.messages.len() == 128 {
            conversation.messages.remove(0);
        }
        conversation.messages.push(Message {
            id: id.into(),
            sender: clean(payload["sender"].as_str().unwrap_or("peer")),
            text: clean(text),
            outgoing,
            delivery: delivery(payload),
        });
        if index != self.selected && !outgoing {
            conversation.unread = conversation.unread.saturating_add(1);
        }
        if index == self.selected && self.scroll_offset > 0 {
            self.scroll_offset = self.scroll_offset.saturating_add(1);
        }
    }

    pub fn select_next(&mut self, backwards: bool) {
        if self.conversations.is_empty() {
            return;
        }
        let count = self.conversations.len();
        self.selected = if backwards {
            (self.selected + count - 1) % count
        } else {
            (self.selected + 1) % count
        };
        self.conversations[self.selected].unread = 0;
        self.scroll_offset = 0;
    }

    pub fn scroll(&mut self, older: bool, rows: usize) {
        self.scroll_offset = if older {
            self.scroll_offset
                .saturating_add(rows)
                .min(self.selected_messages().len().saturating_sub(1))
        } else {
            self.scroll_offset.saturating_sub(rows)
        };
    }

    fn visible_messages(&self, rows: usize) -> &[Message] {
        let messages = self.selected_messages();
        let end = messages.len().saturating_sub(self.scroll_offset);
        &messages[end.saturating_sub(rows)..end]
    }
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

        let messages = self.visible_messages(usize::from(body.height));
        for offset in 0..body.height {
            let index = usize::from(offset);
            let y = body.y.saturating_add(offset);
            if let Some(conversation) = self.conversations.get(
                index
                    + self
                        .selected
                        .saturating_sub(usize::from(body.height).saturating_sub(1)),
            ) {
                let marker = if conversation.id == self.conversations[self.selected].id {
                    ">"
                } else {
                    " "
                };
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
            .visible_messages(usize::from(body.height))
            .iter()
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
                    " | /help for controls"
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
            (Some("room-members"), Some(relay), Some(group_id)) if !group_id.contains(' ') => {
                Ok(Some(Command::RoomMembers {
                    relay: relay.into(),
                    group_id: group_id.into(),
                }))
            }
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

// No peer-provided terminal control characters reach the renderer.
fn clean(text: &str) -> String {
    text.chars()
        .filter(|c| !c.is_control())
        .take(4096)
        .collect()
}

fn delivery(payload: &Value) -> Option<DeliveryState> {
    match payload["delivery"].as_str()? {
        "queued" | "created" => Some(DeliveryState::Queued),
        "stored" => Some(DeliveryState::Stored),
        "failed" => Some(DeliveryState::Failed),
        _ => None,
    }
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
            parse_input("/room-members wss://r.example omarchy", None),
            Ok(Some(Command::RoomMembers {
                relay: "wss://r.example".into(),
                group_id: "omarchy".into(),
            }))
        );
        assert_eq!(
            parse_input("hello", Some("room:aa:omarchy")),
            Ok(Some(Command::Send {
                conversation: "room:aa:omarchy".into(),
                text: "hello".into(),
            }))
        );
    }
}
