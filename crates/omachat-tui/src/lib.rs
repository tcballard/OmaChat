//! Terminal model for Nostr direct messages, contacts, relays, and handle binding.
//!
//! The widget uses only the sixteen ANSI colors. Peer text is stripped of
//! control characters before it is drawn.

use omachat_proto::ipc::{Command, Event, Topic};
use ratatui::{
    buffer::Buffer,
    layout::{Constraint, Layout, Rect},
    style::{Color, Modifier, Style},
    widgets::Widget,
};
use serde_json::Value;

const NARROW_WIDTH: u16 = 40;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ContactRow {
    pub peer: String,
    pub title: String,
    pub messages: Vec<MessageRow>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MessageRow {
    pub id: String,
    pub sender: String,
    pub text: String,
    pub outgoing: bool,
    pub delivery: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Action {
    Command(Command),
    Select(String),
    Help,
    Quit,
}

pub struct UiModel {
    pub contacts: Vec<ContactRow>,
    pub selected: usize,
    pub npub: String,
    pub relays: Vec<String>,
    pub input: String,
    pub status: String,
    pub connected: bool,
    pub scroll: usize,
}

impl Default for UiModel {
    fn default() -> Self {
        Self {
            contacts: Vec::new(),
            selected: 0,
            npub: String::new(),
            relays: Vec::new(),
            input: String::new(),
            status: "connecting | /help".into(),
            connected: false,
            scroll: 0,
        }
    }
}

impl Widget for &UiModel {
    fn render(self, area: Rect, buffer: &mut Buffer) {
        let title = Style::new().fg(Color::Cyan).add_modifier(Modifier::BOLD);
        let plain = Style::new().fg(Color::White);
        let bar = Style::new().fg(Color::Black).bg(Color::White);
        if area.width < NARROW_WIDTH || area.height < 8 {
            write(buffer, row(area, area.y), "OmaChat", title);
            write(
                buffer,
                row(area, area.y.saturating_add(1)),
                &self.npub,
                plain,
            );
            write(
                buffer,
                row(area, area.bottom().saturating_sub(1)),
                &self.status,
                bar,
            );
            return;
        }
        let columns = Layout::horizontal([Constraint::Length(28), Constraint::Fill(1)]).split(area);
        write(buffer, row(columns[0], columns[0].y), "OmaChat", title);
        write(
            buffer,
            row(columns[0], columns[0].y.saturating_add(1)),
            "npub",
            title,
        );
        write(
            buffer,
            row(columns[0], columns[0].y.saturating_add(2)),
            &self.npub,
            plain,
        );
        write(
            buffer,
            row(columns[0], columns[0].y.saturating_add(4)),
            "contacts",
            title,
        );
        for (index, contact) in self.contacts.iter().enumerate() {
            let y = columns[0].y.saturating_add(5).saturating_add(index as u16);
            let marker = if index == self.selected { ">" } else { " " };
            write(
                buffer,
                row(columns[0], y),
                &format!("{marker} {}", contact.title),
                plain,
            );
        }
        let peer = self
            .contacts
            .get(self.selected)
            .map(|contact| contact.title.as_str())
            .unwrap_or("no contact selected");
        write(buffer, row(columns[1], columns[1].y), peer, title);
        let messages = self
            .contacts
            .get(self.selected)
            .map(|contact| contact.messages.as_slice())
            .unwrap_or(&[]);
        let visible = usize::from(columns[1].height.saturating_sub(3));
        let start = messages.len().saturating_sub(visible + self.scroll);
        for (offset, message) in messages.iter().skip(start).take(visible).enumerate() {
            let y = columns[1].y.saturating_add(1).saturating_add(offset as u16);
            let line = if message.outgoing {
                format!("you: {} {}", message.text, message.delivery)
            } else {
                format!("{}: {}", message.sender, message.text)
            };
            write(buffer, row(columns[1], y), &line, plain);
        }
        write(
            buffer,
            row(area, area.bottom().saturating_sub(2)),
            &self.status,
            bar,
        );
        write(
            buffer,
            row(area, area.bottom().saturating_sub(1)),
            &format!("> {}", self.input),
            Style::new().fg(Color::Cyan),
        );
    }
}

impl UiModel {
    pub fn apply_snapshot(&mut self, snapshot: &Value) {
        if let Some(npub) = snapshot["identity"]["npub"].as_str() {
            self.npub = npub.to_owned();
        }
        self.relays = snapshot["relays"]
            .as_array()
            .map(|relays| {
                relays
                    .iter()
                    .filter_map(|relay| relay.as_str().map(str::to_owned))
                    .collect()
            })
            .unwrap_or_default();
        if let Some(messages) = snapshot["messages"].as_array() {
            for message in messages {
                self.apply_message(message);
            }
        }
        if let Some(contacts) = snapshot["contacts"].as_array() {
            for contact in contacts {
                let Some(pubkey) = contact["pubkey"].as_str() else {
                    continue;
                };
                let title = contact["display"]
                    .as_str()
                    .or_else(|| contact["npub"].as_str())
                    .unwrap_or(pubkey);
                self.ensure_contact(&format!("dm:{pubkey}"), title);
            }
        }
        self.connected = true;
        self.status = "connected | Tab: contacts | /help".into();
    }

    pub fn apply_event(&mut self, event: &Event) {
        match event.topic {
            Topic::Messages | Topic::Delivery => self.apply_message(&event.payload),
            Topic::Conversations => {
                if let Some(id) = event.payload["conversation"].as_str() {
                    let title = event.payload["name"].as_str().unwrap_or(id);
                    self.ensure_contact(id, title);
                }
            }
            Topic::Status => {
                if let Some(npub) = event.payload["nostr"]["npub"].as_str() {
                    self.npub = npub.to_owned();
                }
            }
            Topic::Presence => {}
        }
    }

    pub fn apply_message(&mut self, payload: &Value) {
        let Some(id) = payload["id"].as_str() else {
            return;
        };
        let Some(conversation) = payload["conversation"].as_str() else {
            return;
        };
        let text = clean(payload["text"].as_str().unwrap_or(""));
        let index = self.ensure_contact(conversation, conversation);
        let contact = &mut self.contacts[index];
        if let Some(existing) = contact.messages.iter_mut().find(|message| message.id == id) {
            if let Some(delivery) = payload["delivery"].as_str() {
                existing.delivery = delivery.to_owned();
            }
            return;
        }
        if contact.messages.len() == 128 {
            contact.messages.remove(0);
        }
        contact.messages.push(MessageRow {
            id: id.to_owned(),
            sender: clean(payload["sender"].as_str().unwrap_or("peer")),
            text,
            outgoing: payload["outgoing"].as_bool().unwrap_or(false),
            delivery: payload["delivery"]
                .as_str()
                .unwrap_or("received")
                .to_owned(),
        });
    }

    pub fn select_next(&mut self, reverse: bool) {
        if self.contacts.is_empty() {
            return;
        }
        self.selected = if reverse {
            self.selected
                .checked_sub(1)
                .unwrap_or(self.contacts.len() - 1)
        } else {
            (self.selected + 1) % self.contacts.len()
        };
        self.scroll = 0;
    }

    pub fn selected_peer(&self) -> Option<&str> {
        self.contacts
            .get(self.selected)
            .map(|contact| contact.peer.as_str())
    }

    fn ensure_contact(&mut self, id: &str, title: &str) -> usize {
        if let Some(index) = self.contacts.iter().position(|contact| contact.peer == id) {
            if !title.is_empty() && !title.starts_with("dm:") {
                self.contacts[index].title = clean(title);
            }
            return index;
        }
        self.contacts.push(ContactRow {
            peer: id.to_owned(),
            title: clean(title),
            messages: Vec::new(),
        });
        self.contacts.len() - 1
    }
}

pub fn parse_input(input: &str, selected_peer: Option<&str>) -> Result<Option<Action>, String> {
    let input = input.trim();
    if input.is_empty() {
        return Ok(None);
    }
    if let Some(arguments) = input.strip_prefix('/') {
        let mut parts = arguments.split_whitespace();
        let command = parts.next().unwrap_or_default();
        let rest = parts.collect::<Vec<_>>();
        return match (command, rest.as_slice()) {
            ("help", []) => Ok(Some(Action::Help)),
            ("quit" | "detach", []) => Ok(Some(Action::Quit)),
            ("npub", []) => Ok(Some(Action::Command(Command::IdentityShow))),
            ("prepare", []) => Ok(Some(Action::Command(Command::ChatPrepare))),
            ("contacts", []) => Ok(Some(Action::Command(Command::ContactsList))),
            ("relays", []) => Ok(Some(Action::Command(Command::RelaysShow))),
            ("contact", ["add", peer]) => Ok(Some(Action::Command(Command::ContactsAdd {
                peer: (*peer).to_owned(),
            }))),
            ("contact", ["remove", npub]) => Ok(Some(Action::Command(Command::ContactsRemove {
                npub: (*npub).to_owned(),
            }))),
            ("handle", ["claim", handle]) => {
                Ok(Some(Action::Command(Command::HostedClaimHandle {
                    handle: (*handle).to_owned(),
                })))
            }
            ("handle", ["bind"]) => Ok(Some(Action::Command(Command::HostedBindNostr))),
            ("handle", ["unbind"]) => Ok(Some(Action::Command(Command::HostedUnbindNostr))),
            ("relays", ["set", urls @ ..]) if !urls.is_empty() => {
                Ok(Some(Action::Command(Command::RelaysSet {
                    relays: urls.iter().map(|url| (*url).to_owned()).collect(),
                })))
            }
            ("open", [peer]) => Ok(Some(Action::Select((*peer).to_owned()))),
            ("panic", [confirmation]) => Ok(Some(Action::Command(Command::Panic {
                confirmation: (*confirmation).to_owned(),
            }))),
            _ => Err("unknown command; /help lists them".into()),
        };
    }
    let peer = selected_peer.ok_or("add a contact with /contact add npub1... or name@domain")?;
    let peer = peer.trim_start_matches("dm:").to_owned();
    Ok(Some(Action::Command(Command::Send {
        peer,
        text: input.to_owned(),
    })))
}

pub const HELP: &str = "/npub /prepare /contact add PEER /contact remove NPUB /contacts /open PEER /relays /relays set URL... /handle claim NAME /handle bind /handle unbind /panic ERASE /quit";

fn write(buffer: &mut Buffer, area: Rect, text: &str, style: Style) {
    if area.is_empty() {
        return;
    }
    buffer.set_stringn(area.x, area.y, clean(text), usize::from(area.width), style);
}

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

fn clean(text: &str) -> String {
    text.chars()
        .map(|character| {
            if character.is_control() && character != '\n' {
                ' '
            } else {
                character
            }
        })
        .take(4096)
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn slash_commands_map_to_nostr_ipc() {
        assert!(matches!(parse_input("/help", None), Ok(Some(Action::Help))));
        assert!(matches!(
            parse_input("/contact add bob@example.com", None),
            Ok(Some(Action::Command(Command::ContactsAdd { .. })))
        ));
        assert!(matches!(
            parse_input("/relays set wss://relay.example ws://127.0.0.1:1", None),
            Ok(Some(Action::Command(Command::RelaysSet { .. })))
        ));
        match parse_input("hello", Some("dm:abc")) {
            Ok(Some(Action::Command(Command::Send { peer, text }))) => {
                assert_eq!(peer, "abc");
                assert_eq!(text, "hello");
            }
            other => panic!("unexpected parse: {other:?}"),
        }
        assert!(parse_input("hello", None).is_err());
        assert!(parse_input("/join general", None).is_err());
    }

    #[test]
    fn snapshot_shows_the_npub_and_a_message() {
        let mut model = UiModel::default();
        model.apply_snapshot(&serde_json::json!({
            "identity": {"present": true, "npub": "npub1example"},
            "relays": ["wss://relay.example"],
            "contacts": [{"pubkey": "aa", "npub": "npub1peer", "display": "ada"}],
            "messages": [{
                "id": "1",
                "conversation": "dm:aa",
                "text": "hi",
                "sender": "ada",
                "outgoing": false,
                "delivery": "received"
            }]
        }));
        assert_eq!(model.npub, "npub1example");
        assert_eq!(model.contacts[0].title, "ada");
        assert_eq!(model.contacts[0].messages[0].text, "hi");
        assert_eq!(model.relays, vec!["wss://relay.example".to_owned()]);
        model.apply_message(&serde_json::json!({
            "id": "2", "conversation": "dm:aa", "text": "another message"
        }));
        assert_eq!(model.contacts[0].title, "ada");
    }
}
