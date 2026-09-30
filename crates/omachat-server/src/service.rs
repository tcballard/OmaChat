//! The single-threaded service actor that owns storage and fan-out.
//!
//! Every session forwards its requests here over a channel; the actor
//! applies them in arrival order against SQLite and pushes events to the
//! sessions of affected accounts. A session whose event queue overflows is
//! flagged as lagged and told to resynchronise from history rather than
//! silently missing messages.

use crate::{
    auth::KEY_BYTES,
    protocol::{
        Command, DEFAULT_HISTORY_LIMIT, EVENT_CONVERSATION, EVENT_MESSAGE, EVENT_RECEIPT,
        ErrorCode, MAX_HISTORY_LIMIT, MAX_INVITE_CODE_BYTES, PROTOCOL_VERSION, ServerError,
        event_frame, validate_client_id, validate_name, validate_text,
    },
    storage::{
        AccountRecord, ConversationSummary, ROLE_OWNER, Receipt, Storage, StorageError,
        StoredMessage,
    },
};
use omachat_crypto::{DisplayName, GlobalHandle};
use serde_json::{Value, json};
use std::{
    collections::{HashMap, HashSet},
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    thread,
};
use tokio::sync::{mpsc, oneshot};

/// Frames buffered per session before it is marked lagged.
pub const EVENT_QUEUE_FRAMES: usize = 256;
const REQUEST_QUEUE_DEPTH: usize = 1024;

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Registration {
    /// Any device key may register an account.
    Open,
    /// Registration requires one of these invite codes.
    Invite(HashSet<String>),
    /// Only devices already known to the server may authenticate.
    Closed,
}

impl Registration {
    pub fn invite_codes(codes: impl IntoIterator<Item = String>) -> Result<Self, ServerError> {
        let mut set = HashSet::new();
        for code in codes {
            let code = code.trim().to_owned();
            if code.is_empty() {
                continue;
            }
            if code.len() > MAX_INVITE_CODE_BYTES {
                return Err(ServerError::new(
                    ErrorCode::InvalidRequest,
                    "invite codes are at most 128 bytes",
                ));
            }
            set.insert(code);
        }
        if set.is_empty() {
            return Err(ServerError::new(
                ErrorCode::InvalidRequest,
                "invite mode needs at least one invite code",
            ));
        }
        Ok(Self::Invite(set))
    }

    #[must_use]
    pub const fn label(&self) -> &'static str {
        match self {
            Self::Open => "open",
            Self::Invite(_) => "invite",
            Self::Closed => "closed",
        }
    }
}

#[derive(Clone, Debug)]
pub struct ServiceConfig {
    pub registration: Registration,
    pub server_public_key: [u8; KEY_BYTES],
}

pub enum ServiceRequest {
    /// Called by a session after the device signature verified.
    Register {
        device_public_key: [u8; KEY_BYTES],
        display_name: Option<String>,
        invite_code: Option<String>,
        now: u64,
    },
    Attach {
        account_id: String,
        session_id: u64,
        events: mpsc::Sender<String>,
        lagged: Arc<AtomicBool>,
    },
    Detach {
        account_id: String,
        session_id: u64,
    },
    Command {
        account_id: String,
        device_public_key: [u8; KEY_BYTES],
        command: Command,
        now: u64,
    },
}

struct ServiceMessage {
    request: ServiceRequest,
    reply: oneshot::Sender<Result<Value, ServerError>>,
}

#[derive(Clone)]
pub struct ServiceHandle {
    sender: mpsc::Sender<ServiceMessage>,
}

impl ServiceHandle {
    pub async fn call(&self, request: ServiceRequest) -> Result<Value, ServerError> {
        let (reply, response) = oneshot::channel();
        self.sender
            .send(ServiceMessage { request, reply })
            .await
            .map_err(|_| ServerError::new(ErrorCode::Internal, "service stopped"))?;
        response
            .await
            .map_err(|_| ServerError::new(ErrorCode::Internal, "service dropped the request"))?
    }
}

/// Start the actor on its own operating-system thread so SQLite calls never
/// block the async runtime.
pub fn spawn_service(storage: Storage, config: ServiceConfig) -> std::io::Result<ServiceHandle> {
    let (sender, mut receiver) = mpsc::channel::<ServiceMessage>(REQUEST_QUEUE_DEPTH);
    thread::Builder::new()
        .name("omachat-service".to_owned())
        .spawn(move || {
            let mut service = Service {
                storage,
                config,
                subscribers: HashMap::new(),
            };
            while let Some(message) = receiver.blocking_recv() {
                let result = service.handle(message.request);
                let _ = message.reply.send(result);
            }
        })?;
    Ok(ServiceHandle { sender })
}

struct Subscriber {
    session_id: u64,
    events: mpsc::Sender<String>,
    lagged: Arc<AtomicBool>,
}

struct Service {
    storage: Storage,
    config: ServiceConfig,
    subscribers: HashMap<String, Vec<Subscriber>>,
}

impl Service {
    fn handle(&mut self, request: ServiceRequest) -> Result<Value, ServerError> {
        match request {
            ServiceRequest::Register {
                device_public_key,
                display_name,
                invite_code,
                now,
            } => self.register(&device_public_key, display_name, invite_code, now),
            ServiceRequest::Attach {
                account_id,
                session_id,
                events,
                lagged,
            } => {
                self.subscribers
                    .entry(account_id)
                    .or_default()
                    .push(Subscriber {
                        session_id,
                        events,
                        lagged,
                    });
                Ok(Value::Null)
            }
            ServiceRequest::Detach {
                account_id,
                session_id,
            } => {
                if let Some(list) = self.subscribers.get_mut(&account_id) {
                    list.retain(|subscriber| subscriber.session_id != session_id);
                    if list.is_empty() {
                        self.subscribers.remove(&account_id);
                    }
                }
                Ok(Value::Null)
            }
            ServiceRequest::Command {
                account_id,
                device_public_key,
                command,
                now,
            } => self.command(&account_id, &device_public_key, command, now),
        }
    }

    fn register(
        &mut self,
        device_public_key: &[u8; KEY_BYTES],
        display_name: Option<String>,
        invite_code: Option<String>,
        now: u64,
    ) -> Result<Value, ServerError> {
        if let Some(account) = self
            .storage
            .account_for_device(device_public_key)
            .map_err(storage_error)?
        {
            self.storage
                .touch_device(device_public_key, now)
                .map_err(storage_error)?;
            return Ok(registration_json(&account, device_public_key, false));
        }
        match &self.config.registration {
            Registration::Open => {}
            Registration::Closed => {
                return Err(ServerError::new(
                    ErrorCode::RegistrationClosed,
                    "this server does not accept new devices",
                ));
            }
            Registration::Invite(codes) => {
                let supplied = invite_code.as_deref().unwrap_or("").trim();
                if supplied.is_empty() || !codes.contains(supplied) {
                    return Err(ServerError::new(
                        ErrorCode::InvalidInvite,
                        "a valid invite code is required to register",
                    ));
                }
            }
        }
        let display_name = match display_name {
            Some(name) => DisplayName::parse(&name)
                .map_err(|_| {
                    ServerError::new(
                        ErrorCode::InvalidName,
                        "display names are 1 to 80 printable characters",
                    )
                })?
                .as_str()
                .to_owned(),
            None => format!("user-{}", &hex::encode(device_public_key)[..8]),
        };
        let account = self
            .storage
            .create_account(device_public_key, &display_name, now)
            .map_err(storage_error)?;
        Ok(registration_json(&account, device_public_key, true))
    }

    fn command(
        &mut self,
        account_id: &str,
        device_public_key: &[u8; KEY_BYTES],
        command: Command,
        now: u64,
    ) -> Result<Value, ServerError> {
        match command {
            Command::Hello { .. } | Command::Authenticate { .. } => Err(ServerError::new(
                ErrorCode::AlreadyAuthenticated,
                "this connection is already authenticated",
            )),
            Command::Status => {
                let account = self.account(account_id)?;
                Ok(json!({
                    "protocol_version": PROTOCOL_VERSION,
                    "account_id": account.id,
                    "handle": account.handle,
                    "display_name": account.display_name,
                    "device_public_key": hex::encode(device_public_key),
                    "server_public_key": hex::encode(self.config.server_public_key),
                    "registration": self.config.registration.label(),
                }))
            }
            Command::ClaimHandle { handle } => {
                let handle = parse_handle(&handle)?;
                self.storage
                    .claim_handle(account_id, handle.as_str())
                    .map_err(storage_error)?;
                Ok(json!({"handle": handle.as_str()}))
            }
            Command::ResolveHandle { handle } => {
                let handle = parse_handle(&handle)?;
                let account = self.resolve(&handle)?;
                Ok(json!({
                    "account_id": account.id,
                    "handle": account.handle,
                    "display_name": account.display_name,
                }))
            }
            Command::CreateWorkspace { name } => {
                validate_name(&name)?;
                let workspace_id = self
                    .storage
                    .create_workspace(&name, account_id, now)
                    .map_err(storage_error)?;
                Ok(json!({"workspace_id": workspace_id, "name": name}))
            }
            Command::AddMember {
                workspace_id,
                handle,
            } => {
                self.require_owner(&workspace_id, account_id)?;
                let handle = parse_handle(&handle)?;
                let member = self.resolve(&handle)?;
                let channels = self
                    .storage
                    .add_workspace_member(&workspace_id, &member.id)
                    .map_err(storage_error)?;
                for channel in &channels {
                    if let Some(summary) = self
                        .storage
                        .conversation(channel, &member.id)
                        .map_err(storage_error)?
                    {
                        self.publish(
                            std::slice::from_ref(&member.id),
                            &event_frame(EVENT_CONVERSATION, conversation_json(&summary)),
                        );
                    }
                }
                Ok(json!({
                    "workspace_id": workspace_id,
                    "account_id": member.id,
                    "channels_joined": channels.len(),
                }))
            }
            Command::CreateChannel { workspace_id, name } => {
                self.require_owner(&workspace_id, account_id)?;
                validate_name(&name)?;
                let conversation_id = self
                    .storage
                    .create_channel(&workspace_id, &name, now)
                    .map_err(storage_error)?;
                let members = self
                    .storage
                    .workspace_member_ids(&workspace_id)
                    .map_err(storage_error)?;
                for member in &members {
                    if let Some(summary) = self
                        .storage
                        .conversation(&conversation_id, member)
                        .map_err(storage_error)?
                    {
                        self.publish(
                            std::slice::from_ref(member),
                            &event_frame(EVENT_CONVERSATION, conversation_json(&summary)),
                        );
                    }
                }
                Ok(json!({"conversation_id": conversation_id, "name": name}))
            }
            Command::OpenDm { handle } => {
                let handle = parse_handle(&handle)?;
                let other = self.resolve(&handle)?;
                if other.id == account_id {
                    return Err(ServerError::new(
                        ErrorCode::InvalidRequest,
                        "a direct conversation needs another account",
                    ));
                }
                let (conversation_id, created) = self
                    .storage
                    .open_dm(account_id, &other.id, now)
                    .map_err(storage_error)?;
                if created
                    && let Some(summary) = self
                        .storage
                        .conversation(&conversation_id, &other.id)
                        .map_err(storage_error)?
                {
                    self.publish(
                        std::slice::from_ref(&other.id),
                        &event_frame(EVENT_CONVERSATION, conversation_json(&summary)),
                    );
                }
                let summary = self
                    .storage
                    .conversation(&conversation_id, account_id)
                    .map_err(storage_error)?
                    .ok_or_else(|| {
                        ServerError::new(ErrorCode::Internal, "conversation vanished")
                    })?;
                Ok(conversation_json(&summary))
            }
            Command::ListConversations => {
                let list = self
                    .storage
                    .conversations_for(account_id)
                    .map_err(storage_error)?;
                Ok(json!({
                    "conversations": list.iter().map(conversation_json).collect::<Vec<_>>(),
                }))
            }
            Command::Send {
                conversation_id,
                client_id,
                text,
            } => {
                validate_client_id(&client_id)?;
                validate_text(&text)?;
                self.require_member(&conversation_id, account_id)?;
                let outcome = self
                    .storage
                    .append_message(
                        &conversation_id,
                        account_id,
                        device_public_key,
                        &client_id,
                        &text,
                        now,
                    )
                    .map_err(storage_error)?;
                if !outcome.duplicate {
                    let members = self
                        .storage
                        .member_ids(&conversation_id)
                        .map_err(storage_error)?;
                    self.publish(
                        &members,
                        &event_frame(EVENT_MESSAGE, message_json(&outcome.message)),
                    );
                }
                Ok(json!({
                    "conversation_id": outcome.message.conversation_id,
                    "sequence": outcome.message.sequence,
                    "id": outcome.message.id,
                    "sent_at": outcome.message.sent_at,
                    "duplicate": outcome.duplicate,
                }))
            }
            Command::History {
                conversation_id,
                before_sequence,
                limit,
            } => {
                self.require_member(&conversation_id, account_id)?;
                let limit = limit
                    .unwrap_or(DEFAULT_HISTORY_LIMIT)
                    .clamp(1, MAX_HISTORY_LIMIT);
                let messages = self
                    .storage
                    .history(&conversation_id, before_sequence.unwrap_or(u64::MAX), limit)
                    .map_err(storage_error)?;
                Ok(json!({
                    "conversation_id": conversation_id,
                    "messages": messages.iter().map(message_json).collect::<Vec<_>>(),
                }))
            }
            Command::MarkDelivered {
                conversation_id,
                sequence,
            } => self.receipt(account_id, &conversation_id, sequence, false),
            Command::MarkRead {
                conversation_id,
                sequence,
            } => self.receipt(account_id, &conversation_id, sequence, true),
        }
    }

    fn receipt(
        &mut self,
        account_id: &str,
        conversation_id: &str,
        sequence: u64,
        read: bool,
    ) -> Result<Value, ServerError> {
        self.require_member(conversation_id, account_id)?;
        let receipt = self
            .storage
            .advance_receipt(conversation_id, account_id, sequence, read)
            .map_err(storage_error)?;
        let members = self
            .storage
            .member_ids(conversation_id)
            .map_err(storage_error)?;
        self.publish(
            &members,
            &event_frame(EVENT_RECEIPT, receipt_json(&receipt)),
        );
        Ok(receipt_json(&receipt))
    }

    fn account(&self, account_id: &str) -> Result<AccountRecord, ServerError> {
        self.storage
            .account(account_id)
            .map_err(storage_error)?
            .ok_or_else(|| ServerError::new(ErrorCode::NotFound, "account no longer exists"))
    }

    fn resolve(&self, handle: &GlobalHandle) -> Result<AccountRecord, ServerError> {
        self.storage
            .resolve_handle(handle.as_str())
            .map_err(storage_error)?
            .ok_or_else(|| ServerError::new(ErrorCode::NotFound, "no account has that handle"))
    }

    fn require_member(&self, conversation_id: &str, account_id: &str) -> Result<(), ServerError> {
        if self
            .storage
            .is_member(conversation_id, account_id)
            .map_err(storage_error)?
        {
            Ok(())
        } else {
            Err(ServerError::new(
                ErrorCode::NotFound,
                "no such conversation for this account",
            ))
        }
    }

    fn require_owner(&self, workspace_id: &str, account_id: &str) -> Result<(), ServerError> {
        match self
            .storage
            .workspace_role(workspace_id, account_id)
            .map_err(storage_error)?
        {
            Some(role) if role == ROLE_OWNER => Ok(()),
            Some(_) => Err(ServerError::new(
                ErrorCode::Forbidden,
                "only a workspace owner may do that",
            )),
            None => Err(ServerError::new(
                ErrorCode::NotFound,
                "no such workspace for this account",
            )),
        }
    }

    fn publish(&mut self, accounts: &[String], frame: &str) {
        for account in accounts {
            let Some(list) = self.subscribers.get_mut(account) else {
                continue;
            };
            list.retain(
                |subscriber| match subscriber.events.try_send(frame.to_owned()) {
                    Ok(()) => true,
                    Err(mpsc::error::TrySendError::Full(_)) => {
                        subscriber.lagged.store(true, Ordering::SeqCst);
                        true
                    }
                    Err(mpsc::error::TrySendError::Closed(_)) => false,
                },
            );
            if list.is_empty() {
                self.subscribers.remove(account);
            }
        }
    }
}

fn parse_handle(value: &str) -> Result<GlobalHandle, ServerError> {
    GlobalHandle::parse(value).map_err(|_| {
        ServerError::new(
            ErrorCode::InvalidHandle,
            "handles are 3 to 32 lowercase letters, digits or '_' and start with a letter",
        )
    })
}

fn storage_error(error: StorageError) -> ServerError {
    match error {
        StorageError::NotFound => ServerError::new(ErrorCode::NotFound, "no such record"),
        StorageError::HandleTaken => {
            ServerError::new(ErrorCode::HandleTaken, "that handle is already taken")
        }
        StorageError::HandleAlreadySet => ServerError::new(
            ErrorCode::HandleAlreadySet,
            "this account already has a handle",
        ),
        StorageError::NameTaken => ServerError::new(
            ErrorCode::NameTaken,
            "that name is already used in this workspace",
        ),
        StorageError::ClientIdReused => ServerError::new(
            ErrorCode::InvalidRequest,
            "client_id was already used for a different conversation",
        ),
        StorageError::SequenceAhead => ServerError::new(
            ErrorCode::InvalidRequest,
            "sequence is ahead of the conversation's last message",
        ),
        other => {
            eprintln!("omachat-serverd: storage failure: {other}");
            ServerError::new(ErrorCode::Storage, "persistent storage failed")
        }
    }
}

fn registration_json(
    account: &AccountRecord,
    device_public_key: &[u8; KEY_BYTES],
    new_account: bool,
) -> Value {
    json!({
        "account_id": account.id,
        "handle": account.handle,
        "display_name": account.display_name,
        "device_public_key": hex::encode(device_public_key),
        "new_account": new_account,
    })
}

#[must_use]
pub fn message_json(message: &StoredMessage) -> Value {
    json!({
        "conversation_id": message.conversation_id,
        "sequence": message.sequence,
        "id": message.id,
        "sender_account_id": message.sender_account_id,
        "sender_device_public_key": hex::encode(message.sender_device_public_key),
        "client_id": message.client_id,
        "sent_at": message.sent_at,
        "text": message.text,
    })
}

#[must_use]
pub fn conversation_json(summary: &ConversationSummary) -> Value {
    json!({
        "conversation_id": summary.id,
        "kind": summary.kind,
        "workspace_id": summary.workspace_id,
        "name": summary.name,
        "last_sequence": summary.last_sequence,
        "delivered_sequence": summary.delivered_sequence,
        "read_sequence": summary.read_sequence,
        "members": summary.members.iter().map(|member| json!({
            "account_id": member.account_id,
            "handle": member.handle,
            "display_name": member.display_name,
        })).collect::<Vec<_>>(),
    })
}

#[must_use]
pub fn receipt_json(receipt: &Receipt) -> Value {
    json!({
        "conversation_id": receipt.conversation_id,
        "account_id": receipt.account_id,
        "delivered_sequence": receipt.delivered_sequence,
        "read_sequence": receipt.read_sequence,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use zeroize::Zeroizing;

    fn service() -> Service {
        Service {
            storage: Storage::open_in_memory(Zeroizing::new([5_u8; 32])).unwrap(),
            config: ServiceConfig {
                registration: Registration::Open,
                server_public_key: [0_u8; KEY_BYTES],
            },
            subscribers: HashMap::new(),
        }
    }

    fn account_id(value: &Value) -> String {
        value["account_id"].as_str().unwrap().to_owned()
    }

    #[test]
    fn overflowing_subscribers_are_flagged_lagged_not_silently_skipped() {
        let mut service = service();
        let ada = account_id(
            &service
                .handle(ServiceRequest::Register {
                    device_public_key: [1_u8; 32],
                    display_name: Some("Ada".into()),
                    invite_code: None,
                    now: 1,
                })
                .unwrap(),
        );
        let bob = account_id(
            &service
                .handle(ServiceRequest::Register {
                    device_public_key: [2_u8; 32],
                    display_name: None,
                    invite_code: None,
                    now: 1,
                })
                .unwrap(),
        );
        service
            .handle(ServiceRequest::Command {
                account_id: bob.clone(),
                device_public_key: [2_u8; 32],
                command: Command::ClaimHandle {
                    handle: "bob".into(),
                },
                now: 2,
            })
            .unwrap();
        let (events, mut inbox) = mpsc::channel(1);
        let lagged = Arc::new(AtomicBool::new(false));
        service
            .handle(ServiceRequest::Attach {
                account_id: bob.clone(),
                session_id: 7,
                events,
                lagged: Arc::clone(&lagged),
            })
            .unwrap();
        let conversation = service
            .handle(ServiceRequest::Command {
                account_id: ada.clone(),
                device_public_key: [1_u8; 32],
                command: Command::OpenDm {
                    handle: "bob".into(),
                },
                now: 3,
            })
            .unwrap()["conversation_id"]
            .as_str()
            .unwrap()
            .to_owned();
        assert!(
            !lagged.load(Ordering::SeqCst),
            "one queued conversation event fits"
        );
        for index in 0..2 {
            service
                .handle(ServiceRequest::Command {
                    account_id: ada.clone(),
                    device_public_key: [1_u8; 32],
                    command: Command::Send {
                        conversation_id: conversation.clone(),
                        client_id: format!("m{index}"),
                        text: "hello".into(),
                    },
                    now: 4,
                })
                .unwrap();
        }
        assert!(
            lagged.load(Ordering::SeqCst),
            "second event overflowed the queue"
        );
        assert!(
            inbox
                .try_recv()
                .unwrap()
                .contains("\"event\":\"conversation\"")
        );
        service
            .handle(ServiceRequest::Detach {
                account_id: bob.clone(),
                session_id: 7,
            })
            .unwrap();
        assert!(service.subscribers.is_empty());
    }

    #[test]
    fn registration_policy_is_enforced_for_new_devices_only() {
        let mut service = service();
        service.config.registration = Registration::invite_codes(["welcome".to_owned()]).unwrap();
        let refused = service
            .handle(ServiceRequest::Register {
                device_public_key: [3_u8; 32],
                display_name: None,
                invite_code: Some("wrong".into()),
                now: 1,
            })
            .unwrap_err();
        assert_eq!(refused.code, ErrorCode::InvalidInvite);
        service
            .handle(ServiceRequest::Register {
                device_public_key: [3_u8; 32],
                display_name: None,
                invite_code: Some(" welcome ".into()),
                now: 1,
            })
            .unwrap();
        service.config.registration = Registration::Closed;
        let known = service
            .handle(ServiceRequest::Register {
                device_public_key: [3_u8; 32],
                display_name: None,
                invite_code: None,
                now: 2,
            })
            .unwrap();
        assert_eq!(known["new_account"], Value::Bool(false));
        let unknown = service
            .handle(ServiceRequest::Register {
                device_public_key: [4_u8; 32],
                display_name: None,
                invite_code: None,
                now: 2,
            })
            .unwrap_err();
        assert_eq!(unknown.code, ErrorCode::RegistrationClosed);
        let bad_name = service.handle(ServiceRequest::Register {
            device_public_key: [5_u8; 32],
            display_name: Some("\u{7}".into()),
            invite_code: None,
            now: 2,
        });
        assert!(bad_name.is_err());
    }
}
