use crate::{
    config::DaemonConfig,
    core_error::CoreError,
    dm_inbox_service::{DmInboxHandle, DmInboxService},
    ipc_server::{EventHub, RequestHandler},
    nostr_service::NostrHandle,
};
use omachat_crypto::{DisplayName, GlobalHandle, IdentitySecrets};
use omachat_nostr::{
    auth::RelayAuthSigner,
    dm_inbox::DmInboxReceive,
    dm_inbox_runtime::DmInboxRuntimeEvent,
    envelope::{CreateEnvelope, RumorShape, create as create_private_envelope},
    event::{EventLimits, SignedEvent, xonly_public_key},
    geochat::{ChatInput, ParsedGeoEvent, create_chat, parse_geo_event, subscription_filter},
    gift_wrap::{ChatRecipient, GiftWrapPersistence, create_chat_rumor, create_gift_wrap},
    mailbox::{MailboxReceive, PrivateMailbox},
    pool::PoolNotification,
    relay::RelayNotification,
};
use omachat_proto::ipc::{Command, ErrorBody, ErrorCode, Event, Request, ResponseOutcome, VERSION};
use omachat_proto::{COMPATIBILITY_PROFILE, geohash::Geohash};
use omachat_store::{
    AccountVault, BlockList, IdentityVault, LocalAccount, NostrDeliveryProfile, NostrOutbox,
    ProviderKind, PublicArchive, PublicArchiveEntry, SealedStore,
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
        atomic::{AtomicU8, AtomicU64, Ordering},
    },
    time::{SystemTime, UNIX_EPOCH},
};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum PanicState {
    Active = 0,
    Erasing = 1,
    CleanupComplete = 2,
    CleanupFailed = 3,
    Stopping = 4,
}

impl PanicState {
    #[must_use]
    pub fn is_terminal(self) -> bool {
        matches!(self, Self::CleanupComplete | Self::CleanupFailed)
    }

    fn from_u8(value: u8) -> Self {
        match value {
            0 => Self::Active,
            1 => Self::Erasing,
            2 => Self::CleanupComplete,
            3 => Self::CleanupFailed,
            4 => Self::Stopping,
            _ => unreachable!("panic lifecycle contains a valid state"),
        }
    }
}

struct PanicLifecycle {
    state: AtomicU8,
    terminal: tokio::sync::watch::Sender<PanicState>,
    transition: Mutex<()>,
}

impl Default for PanicLifecycle {
    fn default() -> Self {
        let (terminal, _) = tokio::sync::watch::channel(PanicState::Active);
        Self {
            state: AtomicU8::new(PanicState::Active as u8),
            terminal,
            transition: Mutex::new(()),
        }
    }
}

impl PanicLifecycle {
    fn state(&self) -> PanicState {
        PanicState::from_u8(self.state.load(Ordering::Acquire))
    }

    fn begin(&self) -> bool {
        let _transition = self.transition();
        self.state
            .compare_exchange(
                PanicState::Active as u8,
                PanicState::Erasing as u8,
                Ordering::AcqRel,
                Ordering::Acquire,
            )
            .is_ok()
    }

    /// Atomically prevent a late panic from starting, or report that an
    /// already-started panic must reach a terminal cleanup state first.
    fn begin_process_shutdown(&self) -> bool {
        let _transition = self.transition();
        match self.state() {
            PanicState::Active => {
                self.state
                    .store(PanicState::Stopping as u8, Ordering::Release);
                false
            }
            PanicState::Erasing => true,
            PanicState::CleanupComplete | PanicState::CleanupFailed | PanicState::Stopping => false,
        }
    }

    fn transition(&self) -> std::sync::MutexGuard<'_, ()> {
        self.transition
            .lock()
            .expect("lifecycle transition mutex poisoned")
    }

    fn finish(&self, succeeded: bool) {
        let terminal = if succeeded {
            PanicState::CleanupComplete
        } else {
            PanicState::CleanupFailed
        };
        self.state.store(terminal as u8, Ordering::Release);
        self.terminal.send_replace(terminal);
    }

    async fn wait_for_terminal(&self) -> PanicState {
        let mut terminal = self.terminal.subscribe();
        loop {
            let state = self.state();
            if state.is_terminal() {
                return state;
            }
            terminal
                .changed()
                .await
                .expect("panic lifecycle sender is owned by the core");
        }
    }
}

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
    operations: tokio::sync::RwLock<()>,
    subscription_transaction: tokio::sync::Mutex<()>,
    outbox_drain: tokio::sync::Mutex<()>,
    panic: PanicLifecycle,
    nostr: Mutex<Option<NostrHandle>>,
    dm_inbox: Mutex<Option<DmInboxHandle>>,
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
    dm_relay_count: usize,
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
                operations: tokio::sync::RwLock::new(()),
                subscription_transaction: tokio::sync::Mutex::new(()),
                outbox_drain: tokio::sync::Mutex::new(()),
                panic: PanicLifecycle::default(),
                nostr: Mutex::new(None),
                dm_inbox: Mutex::new(None),
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
        matches!(
            self.panic_state(),
            PanicState::Erasing | PanicState::CleanupComplete | PanicState::CleanupFailed
        )
    }

    #[must_use]
    pub fn panic_state(&self) -> PanicState {
        self.inner.panic.state()
    }

    /// Wait until panic cleanup has either completed or failed. Merely
    /// entering the erasing state does not satisfy this wait.
    pub async fn wait_for_panic_terminal(&self) -> PanicState {
        self.inner.panic.wait_for_terminal().await
    }

    /// Fence process shutdown against panic erasure. If panic has already
    /// started, this waits for cleanup; otherwise it prevents a late panic
    /// request from starting while the runtime is being dismantled.
    pub async fn prepare_for_shutdown(&self) {
        if self.inner.panic.begin_process_shutdown() {
            self.inner.panic.wait_for_terminal().await;
        }
    }

    pub fn attach_nostr(&self, handle: NostrHandle) -> Result<(), CoreError> {
        self.with_active_transition(move || {
            *self
                .inner
                .nostr
                .lock()
                .expect("Nostr handle mutex poisoned") = Some(handle);
            Ok(())
        })
    }

    pub fn remember_dm_relay_list(
        &self,
        event: &SignedEvent,
        expected_recipient_public_key: &[u8; 32],
        now: u64,
    ) -> Result<omachat_nostr::dm_relay_cache::CacheMutation, CoreError> {
        self.with_active_transition(|| {
            let _storage = self
                .inner
                .storage_transaction
                .lock()
                .expect("storage transaction mutex poisoned");
            crate::dm_relay_cache_store::SealedDmRelayCache::new(&self.inner.store)
                .verify_and_save(
                    event,
                    expected_recipient_public_key,
                    now,
                    &EventLimits::default(),
                    &omachat_nostr::inbox::DmInboxPolicy::default(),
                )
                .map_err(CoreError::DmRelayCache)
        })
    }

    pub async fn discover_dm_relay_list(
        &self,
        recipient_public_key: &[u8; 32],
        now: u64,
    ) -> Result<omachat_nostr::dm_relay_cache::CacheMutation, CoreError> {
        let _operation = self.inner.operations.read().await;
        let (relay_configs, auth_signer) = self.with_active_transition(|| {
            let relay_configs = self
                .inner
                .config
                .lock()
                .expect("config mutex poisoned")
                .dm_relays
                .iter()
                .cloned()
                .map(|url| {
                    omachat_nostr::relay::RelayConfig::new(
                        url,
                        omachat_nostr::relay::RelayRoute::Direct,
                    )
                })
                .collect::<Vec<_>>();
            let identity = self.identity()?;
            let nostr = identity
                .as_ref()
                .expect("checked identity")
                .device_nostr_identity()
                .map_err(CoreError::Identity)?;
            let auth_signer = RelayAuthSigner::from_secret_key(*nostr.private_key())
                .map_err(|_| CoreError::Nostr)?;
            Ok((relay_configs, auth_signer))
        })?;
        let discovered = omachat_nostr::dm_relay_discovery::discover_dm_relay_list(
            relay_configs,
            auth_signer,
            recipient_public_key,
            now,
            &EventLimits::default(),
            &omachat_nostr::inbox::DmInboxPolicy::default(),
            &omachat_nostr::dm_relay_discovery::DmRelayDiscoveryConfig::default(),
        )
        .await
        .map_err(CoreError::DmRelayDiscovery)?;
        self.remember_dm_relay_list(&discovered.event, recipient_public_key, now)
    }

    pub async fn start_dm_inbox(
        &self,
        inbound: tokio::sync::mpsc::Sender<DmInboxRuntimeEvent>,
    ) -> Result<Option<DmInboxService>, CoreError> {
        let (ready, _ready_receiver) = tokio::sync::mpsc::channel(1);
        self.start_dm_inbox_with_ready(inbound, ready).await
    }

    pub async fn start_dm_inbox_with_ready(
        &self,
        inbound: tokio::sync::mpsc::Sender<DmInboxRuntimeEvent>,
        ready: tokio::sync::mpsc::Sender<()>,
    ) -> Result<Option<DmInboxService>, CoreError> {
        let _operation = self.inner.operations.read().await;
        let bootstrap = self.with_active_transition(|| {
            let relays = self
                .inner
                .config
                .lock()
                .expect("config mutex poisoned")
                .dm_relays
                .clone();
            if relays.is_empty() {
                return Ok(None);
            }

            let recipient_secret_key = {
                let identity = self.identity()?;
                let nostr = identity
                    .as_ref()
                    .expect("checked identity")
                    .device_nostr_identity()
                    .map_err(CoreError::Identity)?;
                *nostr.private_key()
            };
            let auth_signer = RelayAuthSigner::from_secret_key(recipient_secret_key)
                .map_err(|_| CoreError::Nostr)?;
            let blocked = self
                .inner
                .state
                .lock()
                .expect("runtime state mutex poisoned")
                .blocked
                .iter()
                .cloned()
                .collect::<Vec<_>>();
            Ok(Some((relays, auth_signer, recipient_secret_key, blocked)))
        })?;
        let Some((relays, auth_signer, recipient_secret_key, blocked)) = bootstrap else {
            return Ok(None);
        };

        let service = DmInboxService::spawn_with_ready(
            &relays,
            auth_signer,
            recipient_secret_key,
            &blocked,
            inbound,
            ready,
        )
        .await
        .map_err(CoreError::DmInbox)?;
        let handle = service.handle();
        if let Err(error) = self.with_active_transition(move || {
            *self
                .inner
                .dm_inbox
                .lock()
                .expect("DM inbox handle mutex poisoned") = Some(handle);
            Ok(())
        }) {
            let _ = service.shutdown().await;
            return Err(error);
        }
        Ok(Some(service))
    }

    pub fn receive_dm_inbox_event(&self, event: DmInboxRuntimeEvent) {
        let _transition = self.inner.panic.transition();
        if self.ensure_active().is_err() {
            return;
        }
        let DmInboxReceive::Message(message) = event.receive else {
            return;
        };
        if self
            .inner
            .state
            .lock()
            .expect("runtime state mutex poisoned")
            .blocked
            .contains(&message.metadata.author_pubkey)
        {
            return;
        }
        self.publish_message_event(
            &message.metadata.gift_wrap_id,
            &format!("dm:{}", message.metadata.author_pubkey),
            &message.content,
            "received",
        );
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
        // Notification processing is synchronous but can copy the private key
        // for envelope decryption and publish plaintext locally. Serialize the
        // whole transition so panic cannot begin between those two actions.
        let _transition = self.inner.panic.transition();
        if self.ensure_active().is_err() {
            return;
        }
        self.receive_active_nostr_notification(notification);
    }

    fn receive_active_nostr_notification(&self, notification: PoolNotification) {
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
        self.with_active_transition(|| self.apply_reload(replacement))
    }

    fn apply_reload(&self, replacement: DaemonConfig) -> Result<(), CoreError> {
        let relay_change_requires_restart = {
            let current = self.inner.config.lock().expect("config mutex poisoned");
            current.relays != replacement.relays || current.dm_relays != replacement.dm_relays
        };
        if relay_change_requires_restart {
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

    fn with_active_transition<T>(
        &self,
        transition: impl FnOnce() -> Result<T, CoreError>,
    ) -> Result<T, CoreError> {
        let _transition = self.inner.panic.transition();
        self.ensure_active()?;
        transition()
    }

    async fn dispatch(&self, command: Command) -> ResponseOutcome {
        let result = match command {
            Command::Panic { confirmation } => {
                if !self.is_active() {
                    return panic_unavailable();
                }
                self.panic_erase(&confirmation).await
            }
            command => {
                if !self.is_active() {
                    return panic_unavailable();
                }
                let _operation = self.inner.operations.read().await;
                if !self.is_active() {
                    return panic_unavailable();
                }
                self.dispatch_active(command).await
            }
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

    async fn dispatch_active(&self, command: Command) -> Result<serde_json::Value, CoreError> {
        match command {
            Command::Status => self.status_value(),
            Command::Fingerprint => self.fingerprint_value(),
            Command::Join { geohash } => self.join(geohash).await,
            Command::Leave { geohash } => self.leave(geohash).await,
            Command::Send { conversation, text } => self.send(&conversation, &text).await,
            Command::DiscoverDmRelays { public_key } => {
                let recipient = decode_xonly(&public_key)?;
                let mutation = self
                    .discover_dm_relay_list(&recipient, unix_time()?)
                    .await?;
                let status = match mutation {
                    omachat_nostr::dm_relay_cache::CacheMutation::Stored => "stored",
                    omachat_nostr::dm_relay_cache::CacheMutation::Unchanged => "unchanged",
                };
                Ok(serde_json::json!({
                    "public_key": hex::encode(recipient),
                    "status": status,
                }))
            }
            Command::Who { geohash } => self.who(&geohash),
            Command::Block { public_key } => self.block(&public_key),
            Command::Subscribe { topics } => Ok(serde_json::json!({"topics": topics})),
            Command::Panic { .. } | Command::Hello { .. } => Err(CoreError::InvalidCommand),
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
            dm_relay_count: config.dm_relays.len(),
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
        if self
            .inner
            .dm_inbox
            .lock()
            .expect("DM inbox handle mutex poisoned")
            .is_some()
        {
            return self
                .send_standard_dm(conversation, text, &peer, &recipient, now)
                .await;
        }
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

    async fn send_standard_dm(
        &self,
        conversation: &str,
        text: &str,
        peer: &str,
        recipient: &[u8; 32],
        now: u64,
    ) -> Result<serde_json::Value, CoreError> {
        let relay_hint = self
            .inner
            .config
            .lock()
            .expect("config mutex poisoned")
            .dm_relays
            .first()
            .cloned();
        let event = {
            let identity = self.identity()?;
            let sender = identity
                .as_ref()
                .expect("checked identity")
                .device_nostr_identity()
                .map_err(CoreError::Identity)?;
            let rumor = create_chat_rumor(
                sender.private_key(),
                now,
                &[ChatRecipient {
                    public_key: *recipient,
                    relay_hint,
                }],
                text.to_owned(),
                None,
                None,
                &EventLimits::default(),
            )
            .map_err(|_| CoreError::Nostr)?;
            create_gift_wrap(
                &rumor,
                sender.private_key(),
                recipient,
                now,
                GiftWrapPersistence::Persistent,
                &EventLimits::default(),
            )
            .map_err(|_| CoreError::Nostr)?
        };
        let gift_wrap = serde_json::to_string(&event).map_err(|_| CoreError::Encoding)?;
        {
            let _storage = self
                .inner
                .storage_transaction
                .lock()
                .expect("storage transaction mutex poisoned");
            self.ensure_active()?;
            NostrOutbox::load(&self.inner.store, now)
                .map_err(CoreError::Outbox)?
                .enqueue_with_profile(&event.id, peer, gift_wrap, NostrDeliveryProfile::Nip17, now)
                .map_err(CoreError::Outbox)?;
        }

        self.drain_outbox().await;
        let delivery = {
            let _storage = self
                .inner
                .storage_transaction
                .lock()
                .expect("storage transaction mutex poisoned");
            self.ensure_active()?;
            let outbox = NostrOutbox::load(&self.inner.store, now).map_err(CoreError::Outbox)?;
            if outbox
                .messages()
                .iter()
                .any(|message| message.id == event.id)
            {
                "queued"
            } else {
                "stored"
            }
        };
        self.publish_message_event(&event.id, conversation, text, delivery);
        Ok(serde_json::json!({"id": event.id, "delivery": delivery}))
    }

    pub async fn drain_outbox(&self) {
        let compatibility_handle = self
            .inner
            .nostr
            .lock()
            .expect("Nostr handle mutex poisoned")
            .clone();
        let nip17_handle = self
            .inner
            .dm_inbox
            .lock()
            .expect("DM inbox handle mutex poisoned")
            .clone();
        if compatibility_handle.is_none() && nip17_handle.is_none() {
            return;
        }
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
                outbox.next_pending().map(|message| {
                    (
                        message.id.clone(),
                        message.peer.clone(),
                        message.gift_wrap.clone(),
                        message.nostr_profile,
                    )
                })
            };
            let Some((id, peer, gift_wrap, nostr_profile)) = pending else {
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
            let outcome = match nostr_profile {
                NostrDeliveryProfile::Compatibility => {
                    let Some(handle) = compatibility_handle.as_ref() else {
                        return;
                    };
                    if handle.publish(event).await.is_ok() {
                        omachat_store::AttemptOutcome::Acknowledged
                    } else {
                        omachat_store::AttemptOutcome::Unavailable
                    }
                }
                NostrDeliveryProfile::Nip17 => {
                    let Some(handle) = nip17_handle.as_ref() else {
                        return;
                    };
                    let recipient = match decode_xonly(&peer) {
                        Ok(recipient) => recipient,
                        Err(_) => {
                            self.record_outbox_attempt(
                                &id,
                                omachat_store::AttemptOutcome::Rejected,
                                now,
                            );
                            return;
                        }
                    };
                    let bootstrap_relays = self
                        .inner
                        .config
                        .lock()
                        .expect("config mutex poisoned")
                        .dm_relays
                        .clone();
                    let route = {
                        let _storage = self
                            .inner
                            .storage_transaction
                            .lock()
                            .expect("storage transaction mutex poisoned");
                        crate::dm_relay_cache_store::SealedDmRelayCache::new(&self.inner.store)
                            .route(
                                &recipient,
                                now,
                                &bootstrap_relays,
                                omachat_nostr::dm_relay_routing::DmRelayRoutingPolicy {
                                    allow_bootstrap_when_missing: true,
                                    ..omachat_nostr::dm_relay_routing::DmRelayRoutingPolicy::default()
                                },
                                &EventLimits::default(),
                                &omachat_nostr::inbox::DmInboxPolicy::default(),
                            )
                    };
                    let published = match route {
                        Ok(route) => {
                            match omachat_nostr::dm_routed_publish::plan_routed_dm_publish(
                                event,
                                route,
                                now,
                                &EventLimits::default(),
                            ) {
                                Ok(plan) => handle.publish(plan).await.is_ok(),
                                Err(_) => false,
                            }
                        }
                        Err(_) => false,
                    };
                    if published {
                        omachat_store::AttemptOutcome::Acknowledged
                    } else {
                        omachat_store::AttemptOutcome::Unavailable
                    }
                }
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
        if self.is_active() {
            Ok(())
        } else {
            Err(CoreError::Panicked)
        }
    }

    fn is_active(&self) -> bool {
        self.panic_state() == PanicState::Active
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
        if !self.inner.panic.begin() {
            return Err(CoreError::Panicked);
        }
        // The request task is not the cleanup owner. A client disconnect,
        // task abort, or server shutdown can drop this await without dropping
        // the independently supervised cleanup operation.
        let supervisor_core = self.clone();
        let supervisor = tokio::spawn(async move {
            let worker_core = supervisor_core.clone();
            let worker = tokio::spawn(async move { worker_core.perform_panic_cleanup().await });
            let result = match worker.await {
                Ok(result) => result,
                Err(_) => Err(CoreError::PanicErase),
            };
            supervisor_core.inner.panic.finish(result.is_ok());
            result
        });
        match supervisor.await {
            Ok(result) => result,
            Err(_) => {
                self.inner.panic.finish(false);
                Err(CoreError::PanicErase)
            }
        }
    }

    async fn perform_panic_cleanup(&self) -> Result<serde_json::Value, CoreError> {
        let dm_inbox = self
            .inner
            .dm_inbox
            .lock()
            .expect("DM inbox handle mutex poisoned")
            .take();
        if let Some(handle) = dm_inbox {
            handle.quiesce().await;
        }

        // Stop relay work before dropping keys. Quiescing rejects new
        // commands, cancels the active publish/subscribe, discards the outer
        // queue, closes every relay, and only then returns.
        let nostr = self
            .inner
            .nostr
            .lock()
            .expect("Nostr handle mutex poisoned")
            .take();
        if let Some(handle) = nostr {
            handle.quiesce().await;
        }

        // Relay cancellation releases commands that were awaiting a publish
        // acknowledgement. The exclusive guard then waits for all other IPC
        // operations to finish and prevents any post-panic mutation or local
        // event publication.
        let _operations = self.inner.operations.write().await;

        // Follow the same identity -> account -> storage lock order used by
        // status/reload, wait for in-flight store work, then destroy all
        // in-process authorities before irreversible external cleanup. A
        // cleanup failure remains terminal.
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
        let erase_result = self
            .inner
            .store
            .panic_erase()
            .await
            .map_err(CoreError::Store);
        self.inner
            .state
            .lock()
            .expect("runtime state mutex poisoned")
            .blocked
            .clear();
        erase_result?;
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

fn panic_unavailable() -> ResponseOutcome {
    ResponseOutcome::Error {
        error: ErrorBody {
            code: ErrorCode::Unavailable,
            message: "daemon is shutting down and unavailable".into(),
        },
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

#[cfg(test)]
mod tests {
    use super::{DaemonCore, PanicLifecycle, PanicState};
    use crate::{DaemonConfig, EventHub, StorageProviderConfig};
    use std::{sync::Arc, time::Duration};
    use tempfile::tempdir;

    #[tokio::test]
    async fn terminal_wait_does_not_complete_when_erasure_only_started() {
        let lifecycle = Arc::new(PanicLifecycle::default());
        assert!(lifecycle.begin());
        assert_eq!(lifecycle.state(), PanicState::Erasing);

        let (release, delayed) = tokio::sync::oneshot::channel();
        let cleanup_lifecycle = Arc::clone(&lifecycle);
        let cleanup = tokio::spawn(async move {
            delayed.await.expect("release delayed cleanup");
            cleanup_lifecycle.finish(true);
        });
        let wait_lifecycle = Arc::clone(&lifecycle);
        let waiter = tokio::spawn(async move { wait_lifecycle.wait_for_terminal().await });

        tokio::task::yield_now().await;
        assert!(!waiter.is_finished());
        release.send(()).expect("cleanup receiver remains live");
        cleanup.await.expect("cleanup task");
        assert_eq!(
            tokio::time::timeout(Duration::from_secs(1), waiter)
                .await
                .expect("terminal waiter wakes")
                .expect("terminal waiter task"),
            PanicState::CleanupComplete
        );
    }

    #[tokio::test]
    async fn panic_cleanup_waits_for_inflight_ipc_operations() {
        let temporary = tempdir().expect("temporary directory");
        let core = DaemonCore::open(
            temporary.path(),
            DaemonConfig {
                storage_provider: StorageProviderConfig::File,
                ..DaemonConfig::default()
            },
            EventHub::default(),
        )
        .await
        .expect("open core");
        let operation = core.inner.operations.read().await;
        let waiting_core = core.clone();
        let waiter = tokio::spawn(async move { waiting_core.wait_for_panic_terminal().await });
        let panic_core = core.clone();
        let panic = tokio::spawn(async move { panic_core.panic_erase("ERASE").await });

        tokio::time::timeout(Duration::from_secs(1), async {
            while core.panic_state() != PanicState::Erasing {
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("panic enters erasing state");
        assert!(!waiter.is_finished());
        assert!(temporary.path().exists(), "store is not erased early");
        let shutdown_core = core.clone();
        let shutdown = tokio::spawn(async move { shutdown_core.prepare_for_shutdown().await });
        tokio::task::yield_now().await;
        assert!(
            !shutdown.is_finished(),
            "process shutdown must wait for terminal panic cleanup"
        );
        panic.abort();
        assert!(
            panic
                .await
                .expect_err("initiating panic task is aborted")
                .is_cancelled()
        );

        drop(operation);
        assert_eq!(
            tokio::time::timeout(Duration::from_secs(1), waiter)
                .await
                .expect("independent cleanup reaches terminal state")
                .expect("terminal waiter"),
            PanicState::CleanupComplete
        );
        tokio::time::timeout(Duration::from_secs(1), shutdown)
            .await
            .expect("process shutdown fence completes")
            .expect("process shutdown task");
        assert!(!temporary.path().exists());
    }

    #[tokio::test]
    async fn process_shutdown_prevents_a_late_panic_from_starting() {
        let temporary = tempdir().expect("temporary directory");
        let core = DaemonCore::open(
            temporary.path(),
            DaemonConfig {
                storage_provider: StorageProviderConfig::File,
                ..DaemonConfig::default()
            },
            EventHub::default(),
        )
        .await
        .expect("open core");

        core.prepare_for_shutdown().await;
        assert_eq!(core.panic_state(), PanicState::Stopping);
        assert!(core.panic_erase("ERASE").await.is_err());
        assert!(temporary.path().exists(), "late panic did not erase state");
    }

    #[test]
    fn panic_begin_waits_for_an_active_reload_transition() {
        let lifecycle = Arc::new(PanicLifecycle::default());
        let transition = lifecycle.transition();
        let (started_sender, started_receiver) = std::sync::mpsc::channel();
        let (result_sender, result_receiver) = std::sync::mpsc::channel();
        let panic_lifecycle = Arc::clone(&lifecycle);
        let panic = std::thread::spawn(move || {
            started_sender.send(()).expect("signal panic thread");
            result_sender
                .send(panic_lifecycle.begin())
                .expect("return panic begin result");
        });

        started_receiver.recv().expect("panic thread started");
        assert!(
            result_receiver
                .recv_timeout(Duration::from_millis(25))
                .is_err(),
            "panic must not begin while reload owns the transition"
        );
        assert_eq!(lifecycle.state(), PanicState::Active);

        drop(transition);
        assert!(
            result_receiver
                .recv_timeout(Duration::from_secs(1))
                .expect("panic begins after transition releases")
        );
        panic.join().expect("panic thread");
        assert_eq!(lifecycle.state(), PanicState::Erasing);
    }
}
