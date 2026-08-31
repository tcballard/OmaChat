use crate::{
    config::DaemonConfig,
    core_error::CoreError,
    ipc_server::{EventHub, RequestHandler},
    nostr_service::NostrHandle,
};
use omachat_crypto::{DisplayName, GlobalHandle, IdentitySecrets};
use omachat_nostr::{
    envelope::{CreateEnvelope, RumorShape, create as create_private_envelope},
    event::{EventLimits, SignedEvent, xonly_public_key},
    geochat::{ChatInput, ParsedGeoEvent, create_chat, parse_geo_event, subscription_filter},
    mailbox::{MailboxReceive, PrivateMailbox},
    pool::PoolNotification,
    relay::RelayNotification,
};
use omachat_proto::ipc::{Command, ErrorBody, ErrorCode, Event, Request, ResponseOutcome, VERSION};
use omachat_proto::{COMPATIBILITY_PROFILE, geohash::Geohash};
use omachat_store::{
    AccountVault, BlockList, IdentityVault, LocalAccount, NostrOutbox, ProviderKind, PublicArchive,
    PublicArchiveEntry, SealedStore,
};
use serde::Serialize;
use serde_json::to_value;
use std::{
    collections::BTreeSet,
    future::Future,
    path::Path,
    pin::Pin,
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, AtomicU64, Ordering},
    },
    time::{SystemTime, UNIX_EPOCH},
};

#[derive(Default)]
struct RuntimeState {
    joined: BTreeSet<String>,
    blocked: BTreeSet<String>,
}
struct CoreInner {
    store: SealedStore,
    identity: Mutex<Option<IdentitySecrets>>,
    account: Mutex<Option<LocalAccount>>,
    storage_transaction: Mutex<()>,
    subscription_transaction: tokio::sync::Mutex<()>,
    outbox_drain: tokio::sync::Mutex<()>,
    panicked: AtomicBool,
    nostr: Mutex<Option<NostrHandle>>,
    mailbox: Mutex<PrivateMailbox>,
    state: Mutex<RuntimeState>,
    config: Mutex<DaemonConfig>,
    events: EventHub,
    sequence: AtomicU64,
}

#[derive(Clone)]
pub struct DaemonCore {
    inner: Arc<CoreInner>,
}

#[derive(Serialize)]
struct DaemonStatus<'a> {
    compatibility_profile: &'a str,
    storage_provider: ProviderKind,
    fingerprint: &'a str,
    peer_id: &'a str,
    nostr_public_key: String,
    joined_geohashes: Vec<String>,
    relay_count: usize,
    outbox_pending: usize,
    outbox_failed: usize,
    account: AccountStatus,
}

#[derive(Serialize)]
struct AccountStatus {
    account_id: String,
    device_id: String,
    handle: Option<String>,
    display_name: Option<String>,
    binding_revision: u64,
    binding_issued_at: u64,
    /// `local-only` is an explicit non-claim: no central registry receipt has
    /// established global uniqueness yet.
    registry_state: &'static str,
}

impl DaemonCore {
    pub async fn open(
        state_directory: impl AsRef<Path>,
        config: DaemonConfig,
        events: EventHub,
    ) -> Result<Self, CoreError> {
        config.validate()?;
        let store = SealedStore::open(&state_directory, config.storage_provider.into())
            .await
            .map_err(CoreError::Store)?;
        let identity = IdentityVault::load_or_create(&store).map_err(CoreError::IdentityStore)?;
        let (configured_handle, configured_display_name) = configured_account_profile(&config)?;
        let account = AccountVault::load_or_create(
            &store,
            &identity,
            configured_handle,
            configured_display_name,
            unix_time()?,
        )
        .map_err(CoreError::AccountVault)?;
        let blocked = BlockList::load(&store)
            .map_err(|_| CoreError::Encoding)?
            .keys()
            .iter()
            .cloned()
            .collect::<BTreeSet<_>>();
        let mut mailbox = PrivateMailbox::new(Default::default()).map_err(|_| CoreError::Nostr)?;
        for public_key in &blocked {
            mailbox
                .block_sender(public_key)
                .map_err(|_| CoreError::InvalidPublicKey)?;
        }
        let joined = config
            .joined_geohashes
            .iter()
            .map(|value| {
                Geohash::parse(value)
                    .map(|geohash| geohash.to_string())
                    .map_err(|_| CoreError::InvalidConfig)
            })
            .collect::<Result<_, _>>()?;
        Ok(Self {
            inner: Arc::new(CoreInner {
                store,
                identity: Mutex::new(Some(identity)),
                account: Mutex::new(Some(account)),
                storage_transaction: Mutex::new(()),
                subscription_transaction: tokio::sync::Mutex::new(()),
                outbox_drain: tokio::sync::Mutex::new(()),
                panicked: AtomicBool::new(false),
                nostr: Mutex::new(None),
                mailbox: Mutex::new(mailbox),
                state: Mutex::new(RuntimeState { joined, blocked }),
                config: Mutex::new(config),
                events,
                sequence: AtomicU64::new(1),
            }),
        })
    }

    #[must_use]
    pub fn events(&self) -> EventHub {
        self.inner.events.clone()
    }

    #[must_use]
    pub fn is_panicked(&self) -> bool {
        self.inner.panicked.load(Ordering::Acquire)
    }

    pub fn attach_nostr(&self, handle: NostrHandle) {
        *self
            .inner
            .nostr
            .lock()
            .expect("Nostr handle mutex poisoned") = Some(handle);
    }

    #[must_use]
    pub fn relay_urls(&self) -> Vec<String> {
        self.inner
            .config
            .lock()
            .expect("config mutex poisoned")
            .relays
            .clone()
    }

    pub fn nostr_filters(&self, now: u64) -> Result<Vec<serde_json::Value>, CoreError> {
        let state = self
            .inner
            .state
            .lock()
            .expect("runtime state mutex poisoned");
        let mut filters = state
            .joined
            .iter()
            .map(|value| {
                let geohash = Geohash::parse(value).expect("stored geohash is validated");
                subscription_filter(&geohash, now.saturating_sub(6 * 60 * 60), 1_000)
            })
            .collect::<Vec<_>>();
        drop(state);
        let identity = self.identity()?;
        let public_key = identity
            .as_ref()
            .expect("checked identity")
            .device_nostr_identity()
            .map_err(CoreError::Identity)?
            .public_key_hex();
        filters.push(
            self.inner
                .mailbox
                .lock()
                .expect("mailbox mutex poisoned")
                .subscription_filter(&public_key, now)
                .map_err(|_| CoreError::Nostr)?,
        );
        Ok(filters)
    }

    pub fn receive_nostr_notification(&self, notification: PoolNotification) {
        if self.is_panicked() {
            return;
        }
        let event = match notification.notification {
            RelayNotification::Connected => {
                let core = self.clone();
                tokio::spawn(async move { core.drain_outbox().await });
                return;
            }
            RelayNotification::Event { event, .. } => event,
            _ => return,
        };
        let Ok(now) = unix_time() else { return };
        if let Ok(parsed) = parse_geo_event(&event, now, &EventLimits::default()) {
            let (geohash, content, topic) = match parsed {
                ParsedGeoEvent::Chat {
                    geohash, content, ..
                } => (geohash, Some(content), omachat_proto::ipc::Topic::Messages),
                ParsedGeoEvent::Presence { geohash, .. } => {
                    (geohash, None, omachat_proto::ipc::Topic::Presence)
                }
            };
            if !self
                .inner
                .state
                .lock()
                .expect("runtime state mutex poisoned")
                .joined
                .contains(geohash.as_str())
            {
                return;
            }
            if let Ok(payload) = serde_json::to_vec(&event) {
                let _storage = self
                    .inner
                    .storage_transaction
                    .lock()
                    .expect("storage transaction mutex poisoned");
                if self.is_panicked() {
                    return;
                }
                if let Ok(mut archive) = PublicArchive::load(&self.inner.store, now) {
                    let _ = archive.insert(
                        PublicArchiveEntry {
                            event_id: event.id.clone(),
                            created_at: event.created_at,
                            payload,
                        },
                        now,
                    );
                }
            }
            self.inner.events.publish(Event { version: VERSION, sequence: self.inner.sequence.fetch_add(1, Ordering::Relaxed), topic, payload: serde_json::json!({"id": event.id, "conversation": format!("#{}", geohash), "text": content}) });
            return;
        }
        let recipient_secret = {
            let Ok(identity) = self.identity() else {
                return;
            };
            let Ok(nostr) = identity
                .as_ref()
                .expect("checked identity")
                .device_nostr_identity()
            else {
                return;
            };
            *nostr.private_key()
        };
        let received = self
            .inner
            .mailbox
            .lock()
            .expect("mailbox mutex poisoned")
            .receive(&event, &recipient_secret, now);
        if let Ok(MailboxReceive::Message(message)) = received {
            self.publish_message_event(
                &message.metadata.gift_wrap_id,
                &format!("dm:{}", message.metadata.sender_pubkey),
                &message.content,
                "received",
            );
        }
    }

    /// Parse and validate completely before replacing the active config.
    pub fn reload(&self, path: impl AsRef<Path>) -> Result<(), CoreError> {
        let replacement = DaemonConfig::load(path)?;
        if self
            .inner
            .config
            .lock()
            .expect("config mutex poisoned")
            .relays
            != replacement.relays
        {
            return Err(CoreError::RestartRequired);
        }
        let joined = replacement
            .joined_geohashes
            .iter()
            .map(|value| Geohash::parse(value).map(|geohash| geohash.to_string()))
            .collect::<Result<BTreeSet<_>, _>>()
            .map_err(|_| CoreError::InvalidConfig)?;
        let (configured_handle, configured_display_name) =
            configured_account_profile(&replacement)?;
        let replacement_account = {
            let identity = self.identity()?;
            let _storage = self
                .inner
                .storage_transaction
                .lock()
                .expect("storage transaction mutex poisoned");
            self.ensure_active()?;
            AccountVault::load_or_create(
                &self.inner.store,
                identity.as_ref().expect("checked identity"),
                configured_handle,
                configured_display_name,
                unix_time()?,
            )
            .map_err(CoreError::AccountVault)?
        };
        self.inner
            .state
            .lock()
            .expect("runtime state mutex poisoned")
            .joined = joined;
        *self.inner.account.lock().expect("account mutex poisoned") = Some(replacement_account);
        *self.inner.config.lock().expect("config mutex poisoned") = replacement;
        let handle = self
            .inner
            .nostr
            .lock()
            .expect("Nostr handle mutex poisoned")
            .clone();
        if let Some(handle) = handle
            && let Ok(filters) = self.nostr_filters(unix_time().unwrap_or_default())
        {
            tokio::spawn(async move {
                let _ = handle.subscribe("omachat-main-v1".into(), filters).await;
            });
        }
        self.publish_status_event();
        Ok(())
    }

    async fn dispatch(&self, command: Command) -> ResponseOutcome {
        if self.inner.panicked.load(Ordering::Acquire) {
            return ResponseOutcome::Error {
                error: ErrorBody {
                    code: ErrorCode::Unavailable,
                    message: "daemon has completed panic erasure and must exit".into(),
                },
            };
        }
        let result = match command {
            Command::Status => self.status_value(),
            Command::Fingerprint => self.fingerprint_value(),
            Command::Join { geohash } => self.join(geohash).await,
            Command::Leave { geohash } => self.leave(geohash).await,
            Command::Send { conversation, text } => self.send(&conversation, &text).await,
            Command::Who { geohash } => self.who(&geohash),
            Command::Block { public_key } => self.block(&public_key),
            Command::Panic { confirmation } => self.panic_erase(&confirmation).await,
            Command::Subscribe { topics } => Ok(serde_json::json!({"topics": topics})),
            Command::Hello { .. } => Err(CoreError::InvalidCommand),
        };
        match result {
            Ok(result) => ResponseOutcome::Ok { result },
            Err(error) => ResponseOutcome::Error {
                error: ErrorBody {
                    code: error.code(),
                    message: error.to_string(),
                },
            },
        }
    }

    fn status_value(&self) -> Result<serde_json::Value, CoreError> {
        let identity = self.identity()?;
        let identity = identity.as_ref().expect("checked identity");
        let public = identity.public_identity();
        let nostr = identity
            .device_nostr_identity()
            .map_err(CoreError::Identity)?;
        let account = self.account_status()?;
        let state = self
            .inner
            .state
            .lock()
            .expect("runtime state mutex poisoned");
        let config = self.inner.config.lock().expect("config mutex poisoned");
        let now = unix_time()?;
        let _storage = self
            .inner
            .storage_transaction
            .lock()
            .expect("storage transaction mutex poisoned");
        self.ensure_active()?;
        let outbox = NostrOutbox::load(&self.inner.store, now).map_err(CoreError::Outbox)?;
        let pending = outbox
            .messages()
            .iter()
            .filter(|message| message.state == omachat_store::OutboxState::Pending)
            .count();
        let failed = outbox.messages().len().saturating_sub(pending);
        to_value(DaemonStatus {
            compatibility_profile: COMPATIBILITY_PROFILE,
            storage_provider: self.inner.store.status().provider,
            fingerprint: &public.fingerprint_hex,
            peer_id: &public.peer_id,
            nostr_public_key: nostr.public_key_hex(),
            joined_geohashes: state.joined.iter().cloned().collect(),
            relay_count: config.relays.len(),
            outbox_pending: pending,
            outbox_failed: failed,
            account,
        })
        .map_err(|_| CoreError::Encoding)
    }

    fn fingerprint_value(&self) -> Result<serde_json::Value, CoreError> {
        let identity = self.identity()?;
        Ok(serde_json::Value::String(
            identity
                .as_ref()
                .expect("checked identity")
                .public_identity()
                .fingerprint_hex,
        ))
    }

    async fn join(&self, value: String) -> Result<serde_json::Value, CoreError> {
        let geohash = Geohash::parse(&value).map_err(|_| CoreError::InvalidGeohash)?;
        let _subscription = self.inner.subscription_transaction.lock().await;
        let inserted = self
            .inner
            .state
            .lock()
            .expect("runtime state mutex poisoned")
            .joined
            .insert(geohash.to_string());
        if let Err(error) = self.refresh_nostr_subscription().await {
            if inserted {
                self.inner
                    .state
                    .lock()
                    .expect("runtime state mutex poisoned")
                    .joined
                    .remove(geohash.as_str());
            }
            return Err(error);
        }
        self.publish_status_event();
        Ok(serde_json::json!({"joined": geohash.as_str()}))
    }

    async fn leave(&self, value: String) -> Result<serde_json::Value, CoreError> {
        let geohash = Geohash::parse(&value).map_err(|_| CoreError::InvalidGeohash)?;
        let _subscription = self.inner.subscription_transaction.lock().await;
        let removed = self
            .inner
            .state
            .lock()
            .expect("runtime state mutex poisoned")
            .joined
            .remove(geohash.as_str());
        if !removed {
            return Err(CoreError::NotJoined);
        }
        if let Err(error) = self.refresh_nostr_subscription().await {
            self.inner
                .state
                .lock()
                .expect("runtime state mutex poisoned")
                .joined
                .insert(geohash.to_string());
            return Err(error);
        }
        self.publish_status_event();
        Ok(serde_json::json!({"left": geohash.as_str()}))
    }

    async fn refresh_nostr_subscription(&self) -> Result<(), CoreError> {
        let handle = self
            .inner
            .nostr
            .lock()
            .expect("Nostr handle mutex poisoned")
            .clone();
        let Some(handle) = handle else {
            return Ok(());
        };
        let filters = self.nostr_filters(unix_time()?)?;
        handle
            .subscribe("omachat-main-v1".into(), filters)
            .await
            .map_err(|_| CoreError::Subscription)
    }

    fn who(&self, value: &str) -> Result<serde_json::Value, CoreError> {
        let geohash = Geohash::parse(value).map_err(|_| CoreError::InvalidGeohash)?;
        let joined = self
            .inner
            .state
            .lock()
            .expect("runtime state mutex poisoned")
            .joined
            .contains(geohash.as_str());
        if !joined {
            return Err(CoreError::NotJoined);
        }
        Ok(serde_json::json!({"geohash": geohash.as_str(), "participants": []}))
    }

    fn block(&self, public_key: &str) -> Result<serde_json::Value, CoreError> {
        let normalized = public_key.to_ascii_lowercase();
        decode_xonly(&normalized)?;
        self.inner
            .state
            .lock()
            .expect("runtime state mutex poisoned")
            .blocked
            .insert(normalized.clone());
        self.inner
            .mailbox
            .lock()
            .expect("mailbox mutex poisoned")
            .block_sender(&normalized)
            .map_err(|_| CoreError::InvalidPublicKey)?;
        let _storage = self
            .inner
            .storage_transaction
            .lock()
            .expect("storage transaction mutex poisoned");
        self.ensure_active()?;
        BlockList::load(&self.inner.store)
            .map_err(|_| CoreError::Encoding)?
            .block(normalized.clone())
            .map_err(|_| CoreError::Encoding)?;
        Ok(serde_json::json!({"blocked": normalized}))
    }

    async fn send(&self, conversation: &str, text: &str) -> Result<serde_json::Value, CoreError> {
        if text.is_empty() || text.len() > 4_096 {
            return Err(CoreError::InvalidMessage);
        }
        let now = unix_time()?;
        if let Ok(geohash) = Geohash::parse(conversation.trim_start_matches('#')) {
            if !self
                .inner
                .state
                .lock()
                .expect("runtime state mutex poisoned")
                .joined
                .contains(geohash.as_str())
            {
                return Err(CoreError::NotJoined);
            }
            let auxiliary = random_bytes()?;
            let nickname = self
                .inner
                .config
                .lock()
                .expect("config mutex poisoned")
                .nickname
                .clone();
            let event = {
                let identity_guard = self.identity()?;
                let identity = identity_guard
                    .as_ref()
                    .expect("checked identity")
                    .derive_geohash_identity(geohash.as_str())
                    .map_err(CoreError::Identity)?;
                create_chat(
                    &ChatInput {
                        secret_key: identity.private_key(),
                        created_at: now,
                        geohash: &geohash,
                        nickname: nickname.as_deref(),
                        teleported: false,
                        content: text,
                        signature_aux: &auxiliary,
                    },
                    &EventLimits::default(),
                )
                .map_err(|_| CoreError::Nostr)?
            };
            let handle = self
                .inner
                .nostr
                .lock()
                .expect("Nostr handle mutex poisoned")
                .clone();
            let delivery = if let Some(handle) = handle {
                handle
                    .publish(event.clone())
                    .await
                    .map_err(CoreError::RelayPool)?;
                "stored"
            } else {
                "created"
            };
            self.publish_message_event(&event.id, conversation, text, delivery);
            return Ok(serde_json::json!({"id": event.id, "delivery": delivery}));
        }

        let peer = conversation
            .strip_prefix("nostr_")
            .or_else(|| conversation.strip_prefix("dm:"))
            .unwrap_or(conversation)
            .to_ascii_lowercase();
        let recipient = decode_xonly(&peer)?;
        let one_time_secret = random_valid_secp()?;
        let seal_nonce = random_bytes()?;
        let gift_wrap_nonce = random_bytes()?;
        let seal_auxiliary = random_bytes()?;
        let gift_auxiliary = random_bytes()?;
        let event = {
            let identity_guard = self.identity()?;
            let sender = identity_guard
                .as_ref()
                .expect("checked identity")
                .device_nostr_identity()
                .map_err(CoreError::Identity)?;
            create_private_envelope(
                &CreateEnvelope {
                    sender_secret_key: sender.private_key(),
                    recipient_xonly_public_key: &recipient,
                    one_time_secret_key: &one_time_secret,
                    content: text,
                    rumor_created_at: now,
                    seal_created_at: now,
                    gift_wrap_created_at: now,
                    seal_nonce: &seal_nonce,
                    gift_wrap_nonce: &gift_wrap_nonce,
                    seal_signature_aux: &seal_auxiliary,
                    gift_wrap_signature_aux: &gift_auxiliary,
                    rumor_shape: RumorShape::AndroidRecipientTag,
                },
                &EventLimits::default(),
            )
            .map_err(|_| CoreError::Nostr)?
        };
        let gift_wrap = serde_json::to_string(&event).map_err(|_| CoreError::Encoding)?;
        let _storage = self
            .inner
            .storage_transaction
            .lock()
            .expect("storage transaction mutex poisoned");
        self.ensure_active()?;
        let mut outbox = NostrOutbox::load(&self.inner.store, now).map_err(CoreError::Outbox)?;
        outbox
            .enqueue(&event.id, &peer, gift_wrap, now)
            .map_err(CoreError::Outbox)?;
        drop(outbox);
        drop(_storage);
        let handle = self
            .inner
            .nostr
            .lock()
            .expect("Nostr handle mutex poisoned")
            .clone();
        let delivery = if let Some(handle) = handle {
            match handle.publish(event.clone()).await {
                Ok(_) => {
                    let _storage = self
                        .inner
                        .storage_transaction
                        .lock()
                        .expect("storage transaction mutex poisoned");
                    self.ensure_active()?;
                    let mut outbox =
                        NostrOutbox::load(&self.inner.store, now).map_err(CoreError::Outbox)?;
                    outbox
                        .record_transport_attempt(
                            &event.id,
                            omachat_store::OutboxTransport::Nostr,
                            omachat_store::AttemptOutcome::Acknowledged,
                            now,
                        )
                        .map_err(CoreError::Outbox)?;
                    "stored"
                }
                Err(_) => {
                    let _storage = self
                        .inner
                        .storage_transaction
                        .lock()
                        .expect("storage transaction mutex poisoned");
                    if self.is_panicked() {
                        return Err(CoreError::Panicked);
                    }
                    if let Ok(mut outbox) = NostrOutbox::load(&self.inner.store, now) {
                        let _ = outbox.record_transport_attempt(
                            &event.id,
                            omachat_store::OutboxTransport::Nostr,
                            omachat_store::AttemptOutcome::Unavailable,
                            now,
                        );
                    }
                    "queued"
                }
            }
        } else {
            "queued"
        };
        self.publish_message_event(&event.id, conversation, text, delivery);
        Ok(serde_json::json!({"id": event.id, "delivery": delivery}))
    }

    async fn drain_outbox(&self) {
        let Some(handle) = self
            .inner
            .nostr
            .lock()
            .expect("Nostr handle mutex poisoned")
            .clone()
        else {
            return;
        };
        let _drain = self.inner.outbox_drain.lock().await;
        loop {
            let now = unix_time().unwrap_or_default();
            let pending = {
                let _storage = self
                    .inner
                    .storage_transaction
                    .lock()
                    .expect("storage transaction mutex poisoned");
                if self.is_panicked() {
                    return;
                }
                let Ok(outbox) = NostrOutbox::load(&self.inner.store, now) else {
                    return;
                };
                outbox
                    .next_pending()
                    .map(|message| (message.id.clone(), message.gift_wrap.clone()))
            };
            let Some((id, gift_wrap)) = pending else {
                return;
            };
            if self.is_panicked() {
                return;
            }
            let event =
                match SignedEvent::from_json(gift_wrap.as_bytes(), now, &EventLimits::default()) {
                    Ok(event) => event,
                    Err(_) => {
                        self.record_outbox_attempt(
                            &id,
                            omachat_store::AttemptOutcome::Rejected,
                            now,
                        );
                        return;
                    }
                };
            let outcome = if handle.publish(event).await.is_ok() {
                omachat_store::AttemptOutcome::Acknowledged
            } else {
                omachat_store::AttemptOutcome::Unavailable
            };
            let state = self.record_outbox_attempt(&id, outcome, now);
            if outcome != omachat_store::AttemptOutcome::Acknowledged {
                if state == Some(omachat_store::OutboxState::Failed) {
                    continue;
                }
                return;
            }
        }
    }

    fn record_outbox_attempt(
        &self,
        id: &str,
        outcome: omachat_store::AttemptOutcome,
        now: u64,
    ) -> Option<omachat_store::OutboxState> {
        let _storage = self
            .inner
            .storage_transaction
            .lock()
            .expect("storage transaction mutex poisoned");
        if self.is_panicked() {
            return None;
        }
        let mut outbox = NostrOutbox::load(&self.inner.store, now).ok()?;
        outbox
            .record_transport_attempt(id, omachat_store::OutboxTransport::Nostr, outcome, now)
            .ok()
    }

    fn identity(&self) -> Result<std::sync::MutexGuard<'_, Option<IdentitySecrets>>, CoreError> {
        let guard = self.inner.identity.lock().expect("identity mutex poisoned");
        if guard.is_none() {
            return Err(CoreError::Panicked);
        }
        Ok(guard)
    }

    fn ensure_active(&self) -> Result<(), CoreError> {
        if self.is_panicked() {
            Err(CoreError::Panicked)
        } else {
            Ok(())
        }
    }

    fn account_status(&self) -> Result<AccountStatus, CoreError> {
        let account = self.inner.account.lock().expect("account mutex poisoned");
        let account = account.as_ref().ok_or(CoreError::Panicked)?;
        let public = account.public_identity();
        let binding = account.binding();
        Ok(AccountStatus {
            account_id: public.account_id.to_string(),
            device_id: binding.device_id.to_string(),
            handle: binding
                .handle
                .as_ref()
                .map(|handle| handle.as_str().to_owned()),
            display_name: binding
                .display_name
                .as_ref()
                .map(|name| name.as_str().to_owned()),
            binding_revision: binding.revision,
            binding_issued_at: binding.issued_at,
            registry_state: if binding.handle.is_some() {
                "local-only"
            } else {
                "unconfigured"
            },
        })
    }

    async fn panic_erase(&self, confirmation: &str) -> Result<serde_json::Value, CoreError> {
        if confirmation != "ERASE" {
            return Err(CoreError::ConfirmationRequired);
        }
        if self
            .inner
            .panicked
            .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
            .is_err()
        {
            return Err(CoreError::Panicked);
        }
        // Follow the same identity -> account -> storage lock order used by
        // status/reload, wait for in-flight store work, then destroy all
        // in-process authorities before beginning irreversible external
        // cleanup. Once panic starts, any cleanup failure is terminal and the
        // daemon remains unavailable.
        {
            let mut identity = self.inner.identity.lock().expect("identity mutex poisoned");
            let mut account = self.inner.account.lock().expect("account mutex poisoned");
            let _storage = self
                .inner
                .storage_transaction
                .lock()
                .expect("storage transaction mutex poisoned");
            identity.take();
            account.take();
        }
        self.inner
            .store
            .panic_erase()
            .await
            .map_err(CoreError::Store)?;
        self.inner
            .state
            .lock()
            .expect("runtime state mutex poisoned")
            .blocked
            .clear();
        Ok(serde_json::json!({"erased": true, "restart_required": true}))
    }

    fn publish_status_event(&self) {
        if let Ok(payload) = self.status_value() {
            self.inner.events.publish(Event {
                version: VERSION,
                sequence: self.inner.sequence.fetch_add(1, Ordering::Relaxed),
                topic: omachat_proto::ipc::Topic::Status,
                payload,
            });
        }
    }

    fn publish_message_event(&self, id: &str, conversation: &str, text: &str, delivery: &str) {
        self.inner.events.publish(Event {
            version: VERSION,
            sequence: self.inner.sequence.fetch_add(1, Ordering::Relaxed),
            topic: omachat_proto::ipc::Topic::Messages,
            payload: serde_json::json!({
                "id": id,
                "conversation": conversation,
                "text": text,
                "delivery": delivery,
            }),
        });
    }
}

impl RequestHandler for DaemonCore {
    fn handle(
        &self,
        request: Request,
    ) -> Pin<Box<dyn Future<Output = ResponseOutcome> + Send + '_>> {
        Box::pin(async move { self.dispatch(request.command).await })
    }
}

fn unix_time() -> Result<u64, CoreError> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .map_err(|_| CoreError::Clock)
}

fn configured_account_profile(
    config: &DaemonConfig,
) -> Result<(Option<GlobalHandle>, Option<DisplayName>), CoreError> {
    let handle = config
        .account_handle
        .as_deref()
        .map(GlobalHandle::parse)
        .transpose()
        .map_err(|_| CoreError::InvalidConfig)?;
    let display_name = config
        .account_display_name
        .as_deref()
        .map(DisplayName::parse)
        .transpose()
        .map_err(|_| CoreError::InvalidConfig)?;
    Ok((handle, display_name))
}

fn random_bytes<const N: usize>() -> Result<[u8; N], CoreError> {
    let mut bytes = [0_u8; N];
    getrandom::fill(&mut bytes).map_err(|_| CoreError::Random)?;
    Ok(bytes)
}

fn random_valid_secp() -> Result<[u8; 32], CoreError> {
    for _ in 0..16 {
        let candidate = random_bytes()?;
        if xonly_public_key(&candidate).is_ok() {
            return Ok(candidate);
        }
    }
    Err(CoreError::Random)
}

fn decode_xonly(value: &str) -> Result<[u8; 32], CoreError> {
    let bytes = hex::decode(value).map_err(|_| CoreError::InvalidPublicKey)?;
    <[u8; 32]>::try_from(bytes).map_err(|_| CoreError::InvalidPublicKey)
}
