//! Deterministic ANSI-16 terminal model and command mapping.

use omachat_proto::ipc::Command;

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

impl UiModel {
    #[must_use]
    pub fn render(&self, width: u16, height: u16) -> String {
        if width < 30 || height < 8 {
            return self.render_narrow(width, height);
        }
        let sidebar_width = usize::from(width / 3).clamp(18, 28);
        let content_width = usize::from(width).saturating_sub(sidebar_width + 3);
        let mut lines = Vec::with_capacity(usize::from(height));
        lines.push(format!(
            "\x1b[1;36m{}\x1b[0m│\x1b[1;37m {}\x1b[0m",
            fit(" Conversations", sidebar_width),
            fit(self.selected_title(), content_width)
        ));
        let body_rows = usize::from(height).saturating_sub(3);
        let messages = self.selected_messages();
        for row in 0..body_rows {
            let conversation = self.conversations.get(row).map_or_else(
                || " ".repeat(sidebar_width),
                |conversation| {
                    let marker = if row == self.selected { ">" } else { " " };
                    let unread = if conversation.unread == 0 {
                        String::new()
                    } else {
                        format!(" ({})", conversation.unread)
                    };
                    fit(
                        &format!("{marker} {}{unread}", conversation.title),
                        sidebar_width,
                    )
                },
            );
            let message = messages.get(row).map_or_else(String::new, render_message);
            lines.push(format!(
                "\x1b[37m{conversation}\x1b[0m│ {}",
                fit(&message, content_width)
            ));
        }
        lines.push(format!(
            "\x1b[30;47m{}\x1b[0m",
            fit(
                &format!(
                    " {} | {:?}{}",
                    self.status,
                    self.input_mode,
                    if self.security_notice_pending {
                        " | relay DMs use mobile-compatible envelopes"
                    } else {
                        ""
                    }
                ),
                usize::from(width)
            )
        ));
        lines.push(format!(
            "\x1b[36m>\x1b[0m {}",
            fit(&self.input, usize::from(width).saturating_sub(2))
        ));
        lines.join("\n")
    }

    fn render_narrow(&self, width: u16, height: u16) -> String {
        let width = usize::from(width);
        let mut lines = vec![format!(
            "\x1b[1;36m{}\x1b[0m",
            fit(self.selected_title(), width)
        )];
        for message in self
            .selected_messages()
            .iter()
            .take(usize::from(height).saturating_sub(3))
        {
            lines.push(fit(&render_message(message), width));
        }
        while lines.len() < usize::from(height).saturating_sub(2) {
            lines.push(" ".repeat(width));
        }
        lines.push(format!("\x1b[7m{}\x1b[0m", fit(&self.status, width)));
        lines.push(fit(&format!("> {}", self.input), width));
        lines.join("\n")
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

fn render_message(message: &Message) -> String {
    let delivery = message.delivery.map_or("", DeliveryState::glyph);
    if message.outgoing {
        format!("you: {} {delivery}", message.text)
    } else {
        format!("{}: {}", message.sender, message.text)
    }
}

fn fit(value: &str, width: usize) -> String {
    let mut fitted = value.chars().take(width).collect::<String>();
    let length = fitted.chars().count();
    fitted.extend(std::iter::repeat_n(' ', width.saturating_sub(length)));
    fitted
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
