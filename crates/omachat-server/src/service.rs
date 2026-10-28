//! The single-threaded service actor that owns storage.
//!
//! Every session forwards its requests here over a channel; the actor
//! applies them in arrival order against SQLite. Sessions still register an
//! event queue so a later relay can fan out without changing the connection
//! loop. Nothing in this process publishes chat events.

use crate::{
    auth::KEY_BYTES,
    protocol::{Command, ErrorCode, PROTOCOL_VERSION, ServerError},
    storage::{AccountRecord, Storage, StorageError},
};
use omachat_crypto::{DisplayName, GlobalHandle};
use serde_json::{Value, json};
use std::{
    collections::HashMap,
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

#[derive(Clone, Debug)]
pub struct ServiceConfig {
    pub server_public_key: [u8; KEY_BYTES],
}

pub enum ServiceRequest {
    /// Called by a session after the device signature verified.
    Register {
        device_public_key: [u8; KEY_BYTES],
        display_name: Option<String>,
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
    // Held so a later relay can publish without changing the session loop.
    #[allow(dead_code)]
    events: mpsc::Sender<String>,
    #[allow(dead_code)]
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
                now,
            } => self.register(&device_public_key, display_name, now),
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
        _now: u64,
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
        }
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

    #[allow(dead_code)]
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

#[cfg(test)]
mod tests {
    use super::*;
    use zeroize::Zeroizing;

    fn service() -> Service {
        Service {
            storage: Storage::open_in_memory(Zeroizing::new([5_u8; 32])).unwrap(),
            config: ServiceConfig {
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
        let bob = account_id(
            &service
                .handle(ServiceRequest::Register {
                    device_public_key: [2_u8; 32],
                    display_name: None,
                    now: 1,
                })
                .unwrap(),
        );
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
        service.publish(std::slice::from_ref(&bob), "one");
        assert!(!lagged.load(Ordering::SeqCst), "one queued frame fits");
        service.publish(std::slice::from_ref(&bob), "two");
        assert!(
            lagged.load(Ordering::SeqCst),
            "the second frame overflowed the queue of one"
        );
        assert_eq!(inbox.try_recv().unwrap(), "one");
        service
            .handle(ServiceRequest::Detach {
                account_id: bob,
                session_id: 7,
            })
            .unwrap();
        assert!(service.subscribers.is_empty());
    }

    #[test]
    fn a_known_device_resumes_and_a_bad_display_name_is_refused() {
        let mut service = service();
        let created = service
            .handle(ServiceRequest::Register {
                device_public_key: [3_u8; 32],
                display_name: Some("Ada".into()),
                now: 1,
            })
            .unwrap();
        assert_eq!(created["new_account"], Value::Bool(true));
        let resumed = service
            .handle(ServiceRequest::Register {
                device_public_key: [3_u8; 32],
                display_name: Some("other".into()),
                now: 2,
            })
            .unwrap();
        assert_eq!(resumed["new_account"], Value::Bool(false));
        assert_eq!(resumed["display_name"], "Ada");
        let bad_name = service.handle(ServiceRequest::Register {
            device_public_key: [5_u8; 32],
            display_name: Some("\u{7}".into()),
            now: 2,
        });
        assert!(bad_name.is_err());
    }
}
