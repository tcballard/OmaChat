use crate::{
    auth::{self, KEY_BYTES},
    protocol::{Command, ErrorCode, PROTOCOL_VERSION, ServerError},
    storage::{AccountRecord, Storage, StorageError},
};
use ed25519_dalek::{Signature, VerifyingKey};
use omachat_crypto::{DisplayName, GlobalHandle, verify_nostr};
use omachat_proto::hosted::{
    NOSTR_PROOF_SKEW_SECONDS, nostr_bind_transcript, nostr_unbind_transcript,
};
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
    /// Optional NIP-05 `relays` list. Empty omits the field.
    pub nip05_relays: Vec<String>,
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
    /// `name` is the decoded NIP-05 local part, or empty when `name` is absent.
    Nip05 {
        name: String,
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
            ServiceRequest::Nip05 { name } => self.nip05(&name),
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
        now: u64,
    ) -> Result<Value, ServerError> {
        match command {
            Command::Hello { .. } | Command::Authenticate { .. } => Err(ServerError::new(
                ErrorCode::AlreadyAuthenticated,
                "this connection is already authenticated",
            )),
            Command::Status => {
                let account = self.account(account_id)?;
                let nostr_public_key = self
                    .storage
                    .nostr_pubkey(account_id)
                    .map_err(storage_error)?
                    .map(hex::encode);
                Ok(json!({
                    "protocol_version": PROTOCOL_VERSION,
                    "account_id": account.id,
                    "handle": account.handle,
                    "display_name": account.display_name,
                    "device_public_key": hex::encode(device_public_key),
                    "server_public_key": hex::encode(self.config.server_public_key),
                    "nostr_public_key": nostr_public_key,
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
            Command::BindNostr {
                nostr_public_key,
                nonce,
                timestamp,
                device_signature,
                nostr_signature,
            } => self.bind_nostr(
                account_id,
                device_public_key,
                &BindProof {
                    nostr_public_key: &nostr_public_key,
                    nonce: &nonce,
                    timestamp,
                    device_signature: &device_signature,
                    nostr_signature: &nostr_signature,
                },
                now,
            ),
            Command::UnbindNostr {
                nonce,
                timestamp,
                device_signature,
            } => self.unbind_nostr(
                account_id,
                device_public_key,
                &nonce,
                timestamp,
                &device_signature,
                now,
            ),
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

    fn bind_nostr(
        &mut self,
        account_id: &str,
        device_public_key: &[u8; KEY_BYTES],
        proof: &BindProof<'_>,
        now: u64,
    ) -> Result<Value, ServerError> {
        let account = self.account(account_id)?;
        let handle = account.handle.ok_or_else(|| {
            ServerError::new(
                ErrorCode::InvalidHandle,
                "claim a handle before binding a nostr key",
            )
        })?;
        let nostr_public_key = decode_nostr_key(proof.nostr_public_key)?;
        let nonce = decode_nostr_key(proof.nonce)?;
        let device_signature = auth::decode_signature(proof.device_signature).map_err(|_| {
            ServerError::new(
                ErrorCode::InvalidRequest,
                "device_signature must be 128 hex characters",
            )
        })?;
        let nostr_signature = auth::decode_signature(proof.nostr_signature).map_err(|_| {
            ServerError::new(
                ErrorCode::InvalidRequest,
                "nostr_signature must be 128 hex characters",
            )
        })?;
        fresh_timestamp(proof.timestamp, now)?;
        let transcript = nostr_bind_transcript(
            &self.config.server_public_key,
            account_id,
            &handle,
            &nostr_public_key,
            &nonce,
            proof.timestamp,
        );
        verify_device(device_public_key, &transcript, &device_signature)?;
        verify_nostr(&nostr_public_key, &transcript, &nostr_signature).map_err(|_| {
            ServerError::new(
                ErrorCode::InvalidSignature,
                "the nostr schnorr signature did not verify",
            )
        })?;
        self.storage
            .remember_proof_nonce(&nonce, account_id, now, NOSTR_PROOF_SKEW_SECONDS)
            .map_err(storage_error)?;
        self.storage
            .bind_nostr(account_id, &nostr_public_key)
            .map_err(storage_error)?;
        Ok(binding_json(&handle, &nostr_public_key))
    }

    fn unbind_nostr(
        &mut self,
        account_id: &str,
        device_public_key: &[u8; KEY_BYTES],
        nonce: &str,
        timestamp: u64,
        device_signature: &str,
        now: u64,
    ) -> Result<Value, ServerError> {
        let account = self.account(account_id)?;
        let handle = account.handle.clone().ok_or_else(|| {
            ServerError::new(ErrorCode::InvalidHandle, "this account has no handle")
        })?;
        let bound = self
            .storage
            .nostr_pubkey(account_id)
            .map_err(storage_error)?
            .ok_or_else(|| ServerError::new(ErrorCode::NotFound, "no nostr key is bound"))?;
        let nonce = decode_nostr_key(nonce)?;
        let device_signature = auth::decode_signature(device_signature).map_err(|_| {
            ServerError::new(
                ErrorCode::InvalidRequest,
                "device_signature must be 128 hex characters",
            )
        })?;
        fresh_timestamp(timestamp, now)?;
        let transcript = nostr_unbind_transcript(
            &self.config.server_public_key,
            account_id,
            &handle,
            &bound,
            &nonce,
            timestamp,
        );
        verify_device(device_public_key, &transcript, &device_signature)?;
        self.storage
            .remember_proof_nonce(&nonce, account_id, now, NOSTR_PROOF_SKEW_SECONDS)
            .map_err(storage_error)?;
        self.storage
            .unbind_nostr(account_id)
            .map_err(storage_error)?;
        Ok(json!({"handle": handle, "nostr_public_key": Value::Null}))
    }

    fn nip05(&self, name: &str) -> Result<Value, ServerError> {
        if name.is_empty() {
            return Err(ServerError::new(
                ErrorCode::InvalidRequest,
                "name query parameter is required",
            ));
        }
        let name = name.to_ascii_lowercase();
        if name.len() > 64
            || !name.bytes().all(|byte| {
                byte.is_ascii_lowercase()
                    || byte.is_ascii_digit()
                    || matches!(byte, b'-' | b'_' | b'.')
            })
        {
            return Err(ServerError::new(
                ErrorCode::InvalidName,
                "nip-05 names are 1 to 64 characters from a-z, 0-9, '-', '_' and '.'",
            ));
        }
        let Some(public_key) = self
            .storage
            .nostr_for_handle(&name)
            .map_err(storage_error)?
        else {
            return Err(ServerError::new(
                ErrorCode::NotFound,
                "no nostr key for that name",
            ));
        };
        let hex_key = hex::encode(public_key);
        let mut names = serde_json::Map::new();
        names.insert(name, json!(hex_key));
        let mut document = json!({"names": names});
        if !self.config.nip05_relays.is_empty() {
            document["relays"] = json!({ &hex_key: self.config.nip05_relays });
        }
        Ok(document)
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

struct BindProof<'a> {
    nostr_public_key: &'a str,
    nonce: &'a str,
    timestamp: u64,
    device_signature: &'a str,
    nostr_signature: &'a str,
}

fn binding_json(handle: &str, nostr_public_key: &[u8; KEY_BYTES]) -> Value {
    json!({
        "handle": handle,
        "nostr_public_key": hex::encode(nostr_public_key),
        "npub": omachat_crypto::npub_from_public_key(nostr_public_key).expect("bound key encodes"),
    })
}

fn decode_nostr_key(value: &str) -> Result<[u8; KEY_BYTES], ServerError> {
    auth::decode_key(value)
        .map_err(|_| ServerError::new(ErrorCode::InvalidRequest, "expected 64 hex characters"))
}

fn fresh_timestamp(timestamp: u64, now: u64) -> Result<(), ServerError> {
    let skew = NOSTR_PROOF_SKEW_SECONDS;
    if timestamp <= now.saturating_add(skew) && now.saturating_sub(skew) <= timestamp {
        Ok(())
    } else {
        Err(ServerError::new(
            ErrorCode::InvalidRequest,
            "nostr proof timestamp is outside the freshness window",
        ))
    }
}

fn verify_device(
    device_public_key: &[u8; KEY_BYTES],
    transcript: &[u8],
    signature: &[u8; 64],
) -> Result<(), ServerError> {
    VerifyingKey::from_bytes(device_public_key)
        .map_err(|_| ServerError::new(ErrorCode::InvalidRequest, "device key is not Ed25519"))?
        .verify_strict(transcript, &Signature::from_bytes(signature))
        .map_err(|_| {
            ServerError::new(
                ErrorCode::InvalidSignature,
                "the device signature did not verify for this nostr proof",
            )
        })
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
        StorageError::NostrPubkeyTaken => ServerError::new(
            ErrorCode::NostrPubkeyTaken,
            "that nostr public key is already bound to another handle",
        ),
        StorageError::ReplayedProof => ServerError::new(
            ErrorCode::ReplayedProof,
            "that nostr proof was already used",
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
                nip05_relays: Vec::new(),
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

    #[test]
    fn nip05_includes_relays_only_when_configured() {
        let mut service = service();
        let account = account_id(
            &service
                .handle(ServiceRequest::Register {
                    device_public_key: [1_u8; 32],
                    display_name: Some("Ada".into()),
                    now: 1,
                })
                .unwrap(),
        );
        service
            .handle(ServiceRequest::Command {
                account_id: account.clone(),
                device_public_key: [1_u8; 32],
                command: Command::ClaimHandle {
                    handle: "ada".into(),
                },
                now: 2,
            })
            .unwrap();
        let key = [9_u8; 32];
        service.storage.bind_nostr(&account, &key).unwrap();
        let plain = service
            .handle(ServiceRequest::Nip05 { name: "Ada".into() })
            .unwrap();
        assert!(plain.get("relays").is_none());
        assert_eq!(plain["names"]["ada"], json!(hex::encode(key)));
        service.config.nip05_relays = vec!["wss://relay.example".into()];
        let with_relays = service
            .handle(ServiceRequest::Nip05 { name: "ada".into() })
            .unwrap();
        assert_eq!(
            with_relays["relays"][hex::encode(key)][0],
            json!("wss://relay.example")
        );
        assert!(
            service
                .handle(ServiceRequest::Nip05 {
                    name: "nope".into()
                })
                .is_err()
        );
        assert!(
            service
                .handle(ServiceRequest::Nip05 {
                    name: "bad name".into()
                })
                .is_err()
        );
    }
}
