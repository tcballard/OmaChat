use crate::{
    CoreError, DaemonConfig,
    hosted_service::{
        DeviceSigner, HostedAccount, HostedError, HostedEvent, HostedHandle, HostedService,
        HostedServiceConfig, HostedState, HostedTimeouts, hosted_conversation_id,
        parse_hosted_conversation,
    },
    ipc_server::{EventHub, RequestHandler},
};
use omachat_crypto::IdentitySecrets;
use omachat_proto::ipc::{Command, ErrorBody, ErrorCode, Event, Request, ResponseOutcome, VERSION};
use omachat_store::{IdentityVault, SealedStore};
use serde::Serialize;
use std::{
    collections::BTreeMap,
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

struct CoreInner {
    store: Arc<SealedStore>,
    chat_history: Mutex<crate::chat_history::ChatHistory>,
    identity: Mutex<Option<IdentitySecrets>>,
    storage_transaction: Mutex<()>,
    operations: tokio::sync::RwLock<()>,
    panic: PanicLifecycle,
    hosted: Mutex<Option<HostedHandle>>,
    /// Last account the hosted server authenticated; kept across
    /// reconnects so status stays truthful while disconnected.
    hosted_account: Mutex<Option<HostedAccount>>,
    /// Conversation summaries by server conversation id, refreshed on every
    /// connect and by `conversation` events. Used for member names and
    /// receipt bookkeeping only; the server remains the source of truth.
    hosted_conversations: Mutex<BTreeMap<String, serde_json::Value>>,
    /// Sends whose outcome is unknown, so a repeat of the same text to the
    /// same conversation reuses its client identifier and cannot duplicate.
    hosted_unacknowledged: Mutex<Vec<UnacknowledgedSend>>,
    config: Mutex<DaemonConfig>,
    events: EventHub,
    sequence: AtomicU64,
    confirmations: crate::confirmation::DestructiveConfirmations,
}

#[derive(Clone)]
pub struct DaemonCore {
    inner: Arc<CoreInner>,
}

/// Hosted transport state for `status`. `disabled` means no `hosted`
/// configuration; every other state describes the live connection.
#[derive(Serialize)]
struct HostedStatus {
    state: &'static str,
    url: Option<String>,
    server_public_key: Option<String>,
    account_id: Option<String>,
    handle: Option<String>,
    display_name: Option<String>,
    reason: Option<String>,
}

struct UnacknowledgedSend {
    conversation_id: String,
    text: String,
    client_id: String,
    recorded_at: u64,
}

const HOSTED_UNACKNOWLEDGED_TTL_SECONDS: u64 = 10 * 60;
const HOSTED_UNACKNOWLEDGED_LIMIT: usize = 64;
const HOSTED_MEMBERS_PER_CONVERSATION: usize = 32;
/// Budget for one IPC response body, leaving room for the envelope under
/// [`omachat_proto::ipc::MAX_LINE_BYTES`].
const HOSTED_IPC_BUDGET_BYTES: usize = 48 * 1024;

impl DaemonCore {
    pub async fn open(
        state_directory: impl AsRef<Path>,
        config: DaemonConfig,
        events: EventHub,
    ) -> Result<Self, CoreError> {
        config.validate()?;
        let store = Arc::new(
            SealedStore::open(&state_directory, config.storage_provider.into())
                .await
                .map_err(CoreError::Store)?,
        );
        let identity = IdentityVault::load_or_create(&store).map_err(CoreError::IdentityStore)?;
        let chat_history = crate::chat_history::ChatHistory::load(&store, unix_time()?)?;
        Ok(Self {
            inner: Arc::new(CoreInner {
                store,
                identity: Mutex::new(Some(identity)),
                chat_history: Mutex::new(chat_history),
                storage_transaction: Mutex::new(()),
                operations: tokio::sync::RwLock::new(()),
                panic: PanicLifecycle::default(),
                hosted: Mutex::new(None),
                hosted_account: Mutex::new(None),
                hosted_conversations: Mutex::new(BTreeMap::new()),
                hosted_unacknowledged: Mutex::new(Vec::new()),
                config: Mutex::new(config),
                events,
                sequence: AtomicU64::new(1),
                confirmations: crate::confirmation::DestructiveConfirmations::new(
                    state_directory.as_ref(),
                ),
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
    pub fn reload(&self, path: impl AsRef<Path>) -> Result<(), CoreError> {
        let replacement = DaemonConfig::load(path)?;
        self.with_active_transition(|| {
            let mut config = self.inner.config.lock().expect("config mutex poisoned");
            if config.hosted != replacement.hosted
                || config.storage_provider != replacement.storage_provider
            {
                return Err(CoreError::RestartRequired);
            }
            *config = replacement;
            Ok(())
        })
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
            Command::Send { conversation, text } => self.send(&conversation, &text).await,
            Command::ListDrafts | Command::GetDraft { .. } | Command::SaveDraft { .. } => {
                let _storage = self
                    .inner
                    .storage_transaction
                    .lock()
                    .expect("storage transaction mutex poisoned");
                self.ensure_active()?;
                crate::drafts::dispatch(&self.inner.store, command)
            }
            Command::RequestPanicConfirmation => {
                let issued = self.inner.confirmations.issue(
                    crate::confirmation::ConfirmationAction::PanicErase,
                    unix_time()?,
                )?;
                Ok(confirmation_issue_value(&issued))
            }
            Command::HostedConversations => self.hosted_conversations(None).await,
            Command::HostedConversationsPage { cursor } => {
                self.hosted_conversations(Some(cursor)).await
            }
            Command::HostedHistory {
                conversation,
                before_sequence,
                limit,
            } => {
                self.hosted_history(&conversation, before_sequence, limit)
                    .await
            }
            Command::HostedMarkRead {
                conversation,
                sequence,
            } => self.hosted_mark_read(&conversation, sequence).await,
            Command::HostedOpenDm { handle } => self.hosted_open_dm(&handle).await,
            Command::HostedClaimHandle { handle } => self.hosted_claim_handle(&handle).await,
            Command::HostedResolveHandle { handle } => {
                self.hosted_call("resolve-handle", serde_json::json!({"handle": handle}))
                    .await
            }
            Command::HostedCreateWorkspace { name } => {
                self.hosted_call("create-workspace", serde_json::json!({"name": name}))
                    .await
            }
            Command::HostedCreateChannel { workspace_id, name } => {
                self.hosted_create_channel(&workspace_id, &name).await
            }
            Command::HostedAddMember {
                workspace_id,
                handle,
            } => {
                self.hosted_call(
                    "add-member",
                    serde_json::json!({"workspace_id": workspace_id, "handle": handle}),
                )
                .await
            }
            Command::Subscribe { topics } => {
                let messages = if topics.contains(&omachat_proto::ipc::Topic::Messages) {
                    self.inner
                        .chat_history
                        .lock()
                        .expect("chat history mutex poisoned")
                        .snapshot(&self.inner.store, unix_time()?)?
                } else {
                    Vec::new()
                };
                Ok(
                    serde_json::json!({"topics": topics, "status": self.status_value()?, "messages": messages}),
                )
            }
            Command::Panic { .. } | Command::Hello { .. } => Err(CoreError::InvalidCommand),
        }
    }

    fn status_value(&self) -> Result<serde_json::Value, CoreError> {
        self.ensure_active()?;
        let identity = self.identity()?;
        let public = identity
            .as_ref()
            .expect("checked identity")
            .public_identity();
        Ok(
            serde_json::json!({"storage_provider": self.inner.store.status().provider, "fingerprint": public.fingerprint_hex, "device_public_key": hex::encode(public.signing_public_key), "drafts_version": 1, "hosted": self.hosted_status()}),
        )
    }
    async fn send(&self, conversation: &str, text: &str) -> Result<serde_json::Value, CoreError> {
        if text.trim().is_empty() || text.len() > 4096 {
            return Err(CoreError::InvalidMessage);
        }
        omachat_proto::hosted::validate_text(text).map_err(CoreError::Hosted)?;
        let id = parse_hosted_conversation(conversation).ok_or(CoreError::InvalidConversation)?;
        self.send_hosted(id, text, unix_time()?).await
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

    async fn panic_erase(&self, confirmation: &str) -> Result<serde_json::Value, CoreError> {
        self.inner
            .confirmations
            .redeem(
                &crate::confirmation::ConfirmationAction::PanicErase,
                confirmation,
                unix_time()?,
            )
            .map_err(|error| match error {
                crate::confirmation::ConfirmationError::Expired => CoreError::ConfirmationExpired,
                crate::confirmation::ConfirmationError::Missing
                | crate::confirmation::ConfirmationError::Mismatch => {
                    CoreError::ConfirmationRequired
                }
            })?;
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
        let hosted = self
            .inner
            .hosted
            .lock()
            .expect("hosted mutex poisoned")
            .take();
        if let Some(handle) = hosted {
            handle.quiesce().await;
        }
        let _operations = self.inner.operations.write().await;
        {
            let mut identity = self.inner.identity.lock().expect("identity mutex poisoned");
            let _storage = self
                .inner
                .storage_transaction
                .lock()
                .expect("storage transaction mutex poisoned");
            identity.take();
        }
        self.inner
            .hosted_account
            .lock()
            .expect("hosted account mutex poisoned")
            .take();
        self.inner
            .hosted_conversations
            .lock()
            .expect("hosted conversations mutex poisoned")
            .clear();
        self.inner
            .hosted_unacknowledged
            .lock()
            .expect("hosted sends mutex poisoned")
            .clear();
        self.inner
            .chat_history
            .lock()
            .expect("chat history mutex poisoned")
            .clear();
        self.inner
            .store
            .panic_erase()
            .await
            .map_err(CoreError::Store)?;
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

    fn publish_topic_event(&self, topic: omachat_proto::ipc::Topic, payload: serde_json::Value) {
        let mut history = self
            .inner
            .chat_history
            .lock()
            .expect("chat history mutex poisoned");
        if self.ensure_active().is_err() {
            return;
        }
        if matches!(
            topic,
            omachat_proto::ipc::Topic::Messages | omachat_proto::ipc::Topic::Delivery
        ) && history
            .update(
                &self.inner.store,
                payload.clone(),
                unix_time().unwrap_or_default(),
            )
            .is_err()
        {
            eprintln!("chat history persistence failed");
        }
        self.inner.events.publish(Event {
            version: VERSION,
            sequence: self.inner.sequence.fetch_add(1, Ordering::Relaxed),
            topic,
            payload,
        });
    }
}
impl DaemonCore {
    /// Start the hosted transport when `hosted` is configured. The returned
    /// service must be shut down before the runtime is dismantled.
    pub fn start_hosted(&self) -> Result<Option<HostedService>, CoreError> {
        self.start_hosted_with(HostedTimeouts::default())
    }

    pub fn start_hosted_with(
        &self,
        timeouts: HostedTimeouts,
    ) -> Result<Option<HostedService>, CoreError> {
        let _transition = self.inner.panic.transition();
        self.ensure_active()?;
        let hosted = {
            let config = self.inner.config.lock().expect("config mutex poisoned");
            config.hosted.clone()
        };
        let Some(hosted) = hosted else {
            return Ok(None);
        };
        let device_public_key = {
            let identity = self.identity()?;
            identity
                .as_ref()
                .expect("checked identity")
                .public_identity()
                .signing_public_key
        };
        let config = HostedServiceConfig {
            url: hosted.canonical_url()?,
            pinned_server_public_key: hosted.pinned_server_public_key_bytes()?,
            device_public_key,
            display_name: hosted
                .display_name
                .clone()
                .filter(|name| omachat_proto::hosted::validate_name(name).is_ok()),
            invite_code: hosted.invite_code.clone(),
            timeouts,
        };
        let signer_core = self.clone();
        let signer: DeviceSigner =
            Arc::new(move |transcript| signer_core.sign_with_device_key(transcript));
        let (event_sender, mut event_receiver) = tokio::sync::mpsc::channel(256);
        let service =
            HostedService::spawn(config, signer, event_sender).map_err(CoreError::HostedService)?;
        *self
            .inner
            .hosted
            .lock()
            .expect("hosted handle mutex poisoned") = Some(service.handle());
        let consumer = self.clone();
        tokio::spawn(async move {
            while let Some(event) = event_receiver.recv().await {
                consumer.receive_hosted_event(event).await;
            }
        });
        Ok(Some(service))
    }

    /// Sign the hosted authentication transcript with the device signing
    /// key. Returns `None` once the identity has been erased, which stops
    /// the transport instead of letting it reconnect as nobody.
    fn sign_with_device_key(&self, transcript: &[u8]) -> Option<[u8; 64]> {
        let guard = self.inner.identity.lock().expect("identity mutex poisoned");
        guard.as_ref().map(|identity| identity.sign(transcript))
    }

    fn hosted_handle(&self) -> Result<HostedHandle, CoreError> {
        self.inner
            .hosted
            .lock()
            .expect("hosted handle mutex poisoned")
            .clone()
            .ok_or(CoreError::HostedUnconfigured)
    }

    fn hosted_account_id(&self) -> Option<String> {
        self.inner
            .hosted_account
            .lock()
            .expect("hosted account mutex poisoned")
            .as_ref()
            .map(|account| account.account_id.clone())
    }

    fn hosted_status(&self) -> HostedStatus {
        let hosted = self
            .inner
            .config
            .lock()
            .expect("config mutex poisoned")
            .hosted
            .clone();
        let Some(hosted) = hosted else {
            return HostedStatus {
                state: "disabled",
                url: None,
                server_public_key: None,
                account_id: None,
                handle: None,
                display_name: None,
                reason: None,
            };
        };
        let state = self
            .inner
            .hosted
            .lock()
            .expect("hosted handle mutex poisoned")
            .as_ref()
            .map(HostedHandle::state);
        let account = self
            .inner
            .hosted_account
            .lock()
            .expect("hosted account mutex poisoned")
            .clone();
        let (state, reason) = match state {
            None => ("starting", None),
            Some(HostedState::Disconnected { reason }) => ("disconnected", Some(reason)),
            Some(other) => (other.label(), None),
        };
        HostedStatus {
            state,
            url: Some(hosted.url),
            server_public_key: Some(hosted.pinned_server_public_key),
            account_id: account.as_ref().map(|account| account.account_id.clone()),
            handle: account.as_ref().and_then(|account| account.handle.clone()),
            display_name: account.and_then(|account| account.display_name),
            reason,
        }
    }

    async fn receive_hosted_event(&self, event: HostedEvent) {
        let _operation = self.inner.operations.read().await;
        if !self.is_active() {
            return;
        }
        match event {
            HostedEvent::State(state) => {
                let connected = state.account().cloned();
                if let Some(account) = connected.clone() {
                    *self
                        .inner
                        .hosted_account
                        .lock()
                        .expect("hosted account mutex poisoned") = Some(account);
                }
                self.publish_status_event();
                if connected.is_some() {
                    // Off the event path: a round trip here would stall the
                    // session loop that has to deliver the reply.
                    let core = self.clone();
                    tokio::spawn(async move { core.resync_hosted().await });
                }
            }
            HostedEvent::Server { kind, data } => match kind.as_str() {
                omachat_proto::hosted::EVENT_MESSAGE => self.receive_hosted_message(data).await,
                omachat_proto::hosted::EVENT_RECEIPT => self.receive_hosted_receipt(&data),
                omachat_proto::hosted::EVENT_CONVERSATION => {
                    self.receive_hosted_conversation(data);
                }
                // `lagged`: the server closes the session next; the
                // reconnect resynchronises from the server's copy.
                _ => {}
            },
        }
    }

    /// Reload the conversation list after (re)connecting and announce every
    /// conversation, so a subscribed client sees the full set again.
    async fn resync_hosted(&self) {
        let _operation = self.inner.operations.read().await;
        if !self.is_active() {
            return;
        }
        let Ok(handle) = self.hosted_handle() else {
            return;
        };
        let mut cursor = None;
        // Bounded background refresh; clients can explicitly page further.
        for _ in 0..128 {
            let result = match &cursor {
                None => {
                    handle
                        .call("list-conversations", serde_json::Value::Null)
                        .await
                }
                Some(value) => {
                    handle
                        .call(
                            "list-conversations-page",
                            serde_json::json!({"cursor": value}),
                        )
                        .await
                }
            };
            let Ok(list) = result else {
                return;
            };
            for summary in self.cache_hosted_conversations(&list) {
                self.publish_topic_event(
                    omachat_proto::ipc::Topic::Conversations,
                    self.hosted_conversation_value(&summary),
                );
            }
            let next = list
                .get("next_cursor")
                .and_then(serde_json::Value::as_str)
                .map(str::to_owned);
            if next.is_none() || next == cursor {
                break;
            }
            cursor = next;
        }
    }

    fn cache_hosted_conversations(&self, list: &serde_json::Value) -> Vec<serde_json::Value> {
        let Some(conversations) = list
            .get("conversations")
            .and_then(serde_json::Value::as_array)
        else {
            return Vec::new();
        };
        let mut cache = self
            .inner
            .hosted_conversations
            .lock()
            .expect("hosted conversations mutex poisoned");
        for summary in conversations {
            if let Some(id) = summary
                .get("conversation_id")
                .and_then(serde_json::Value::as_str)
            {
                cache.insert(id.to_owned(), summary.clone());
            }
        }
        conversations.clone()
    }

    /// IPC shape of a server conversation summary. Direct conversations are
    /// named after the other member; channels keep their name. At most
    /// [`HOSTED_MEMBERS_PER_CONVERSATION`] members are listed so one
    /// conversation can never exceed an IPC line; `member_count` is exact.
    fn hosted_conversation_value(&self, summary: &serde_json::Value) -> serde_json::Value {
        let id = summary
            .get("conversation_id")
            .and_then(serde_json::Value::as_str)
            .unwrap_or_default();
        let own_account = self.hosted_account_id();
        let members = summary
            .get("members")
            .and_then(serde_json::Value::as_array)
            .cloned()
            .unwrap_or_default();
        let name = summary
            .get("name")
            .and_then(serde_json::Value::as_str)
            .map(str::to_owned)
            .or_else(|| {
                members
                    .iter()
                    .find(|member| {
                        member.get("account_id").and_then(serde_json::Value::as_str)
                            != own_account.as_deref()
                    })
                    .map(member_display)
            });
        serde_json::json!({
            "conversation": hosted_conversation_id(id),
            "transport": "hosted",
            "kind": summary.get("kind").cloned().unwrap_or(serde_json::Value::Null),
            "name": name,
            "workspace_id": summary.get("workspace_id").cloned().unwrap_or(serde_json::Value::Null),
            "last_sequence": summary.get("last_sequence").cloned().unwrap_or(serde_json::Value::Null),
            "delivered_sequence": summary.get("delivered_sequence").cloned().unwrap_or(serde_json::Value::Null),
            "read_sequence": summary.get("read_sequence").cloned().unwrap_or(serde_json::Value::Null),
            "receipts": summary.get("receipts").and_then(serde_json::Value::as_array).map(|receipts| receipts.iter().take(HOSTED_MEMBERS_PER_CONVERSATION).map(hosted_receipt_value).collect::<Vec<_>>()).unwrap_or_default(),
            "member_count": summary.get("member_count").cloned().unwrap_or_else(|| serde_json::json!(members.len())),
            "members_truncated": summary.get("members_truncated").cloned().unwrap_or(serde_json::Value::Bool(false)),
            "peer_delivered_sequence": summary.get("peer_delivered_sequence").cloned().unwrap_or(serde_json::Value::Null),
            "peer_read_sequence": summary.get("peer_read_sequence").cloned().unwrap_or(serde_json::Value::Null),
            "members": members.iter().take(HOSTED_MEMBERS_PER_CONVERSATION).cloned().collect::<Vec<_>>(),
        })
    }

    /// IPC shape of a stored message. Own messages are `outgoing` with the
    /// `stored` delivery state; everything else is `received`.
    fn hosted_message_value(&self, message: &serde_json::Value) -> Option<serde_json::Value> {
        let conversation_id = message
            .get("conversation_id")
            .and_then(serde_json::Value::as_str)?;
        let id = message.get("id").and_then(serde_json::Value::as_str)?;
        let text = message.get("text").and_then(serde_json::Value::as_str)?;
        let sender_account_id = message
            .get("sender_account_id")
            .and_then(serde_json::Value::as_str)?;
        let outgoing = self.hosted_account_id().as_deref() == Some(sender_account_id);
        let sender = if outgoing {
            "You".to_owned()
        } else {
            self.hosted_member_name(conversation_id, sender_account_id)
        };
        Some(serde_json::json!({
            "id": id,
            "conversation": hosted_conversation_id(conversation_id),
            "transport": "hosted",
            "text": text,
            "sender": sender,
            "sender_account_id": sender_account_id,
            "outgoing": outgoing,
            "delivery": if outgoing { "stored" } else { "received" },
            "sequence": message.get("sequence").cloned().unwrap_or(serde_json::Value::Null),
            "sent_at": message.get("sent_at").cloned().unwrap_or(serde_json::Value::Null),
        }))
    }

    fn hosted_member_name(&self, conversation_id: &str, account_id: &str) -> String {
        self.inner
            .hosted_conversations
            .lock()
            .expect("hosted conversations mutex poisoned")
            .get(conversation_id)
            .and_then(|summary| summary.get("members")?.as_array().cloned())
            .and_then(|members| {
                members
                    .iter()
                    .find(|member| {
                        member.get("account_id").and_then(serde_json::Value::as_str)
                            == Some(account_id)
                    })
                    .map(member_display)
            })
            .unwrap_or_else(|| account_id.to_owned())
    }

    async fn receive_hosted_message(&self, data: serde_json::Value) {
        let Some(payload) = self.hosted_message_value(&data) else {
            return;
        };
        let outgoing = payload.get("outgoing").and_then(serde_json::Value::as_bool) == Some(true);
        let conversation_id = data
            .get("conversation_id")
            .and_then(serde_json::Value::as_str)
            .unwrap_or_default()
            .to_owned();
        let sequence = data
            .get("sequence")
            .and_then(serde_json::Value::as_u64)
            .unwrap_or_default();
        {
            let mut cache = self
                .inner
                .hosted_conversations
                .lock()
                .expect("hosted conversations mutex poisoned");
            if let Some(summary) = cache.get_mut(&conversation_id) {
                summary["last_sequence"] = serde_json::json!(sequence);
                if outgoing {
                    summary["delivered_sequence"] = serde_json::json!(sequence);
                    summary["read_sequence"] = serde_json::json!(sequence);
                }
            }
        }
        self.publish_topic_event(omachat_proto::ipc::Topic::Messages, payload);
        if !outgoing {
            let core = self.clone();
            tokio::spawn(async move {
                core.mark_hosted_delivered(&conversation_id, sequence).await;
            });
        }
    }

    /// Tell the server a message reached this device. Only ever called for
    /// messages the daemon has actually received.
    async fn mark_hosted_delivered(&self, conversation_id: &str, sequence: u64) {
        let already = self
            .inner
            .hosted_conversations
            .lock()
            .expect("hosted conversations mutex poisoned")
            .get(conversation_id)
            .and_then(|summary| summary.get("delivered_sequence")?.as_u64())
            .unwrap_or_default();
        if sequence == 0 || sequence <= already {
            return;
        }
        let Ok(handle) = self.hosted_handle() else {
            return;
        };
        if handle
            .call(
                "mark-delivered",
                serde_json::json!({"conversation_id": conversation_id, "sequence": sequence}),
            )
            .await
            .is_ok()
            && let Some(summary) = self
                .inner
                .hosted_conversations
                .lock()
                .expect("hosted conversations mutex poisoned")
                .get_mut(conversation_id)
            && summary
                .get("delivered_sequence")
                .and_then(serde_json::Value::as_u64)
                .unwrap_or_default()
                < sequence
        {
            summary["delivered_sequence"] = serde_json::json!(sequence);
        }
    }

    fn receive_hosted_receipt(&self, data: &serde_json::Value) {
        let Some(conversation_id) = data
            .get("conversation_id")
            .and_then(serde_json::Value::as_str)
        else {
            return;
        };
        let account_id = data
            .get("account_id")
            .and_then(serde_json::Value::as_str)
            .unwrap_or_default();
        if self.hosted_account_id().as_deref() == Some(account_id)
            && let Some(summary) = self
                .inner
                .hosted_conversations
                .lock()
                .expect("hosted conversations mutex poisoned")
                .get_mut(conversation_id)
        {
            for field in ["delivered_sequence", "read_sequence"] {
                if let Some(value) = data.get(field).and_then(serde_json::Value::as_u64) {
                    summary[field] = serde_json::json!(value);
                }
            }
        }
        self.publish_topic_event(
            omachat_proto::ipc::Topic::Delivery,
            hosted_receipt_value(data),
        );
    }

    fn receive_hosted_conversation(&self, data: serde_json::Value) {
        if let Some(id) = data
            .get("conversation_id")
            .and_then(serde_json::Value::as_str)
        {
            self.inner
                .hosted_conversations
                .lock()
                .expect("hosted conversations mutex poisoned")
                .insert(id.to_owned(), data.clone());
        }
        self.publish_topic_event(
            omachat_proto::ipc::Topic::Conversations,
            self.hosted_conversation_value(&data),
        );
    }

    /// Send to a hosted conversation with a definite outcome: the server's
    /// sequence, a server refusal, or `HostedUnavailable` once the send
    /// deadline passes. Retries reuse the client identifier, so a repeat can
    /// never store the message twice.
    async fn send_hosted(
        &self,
        conversation_id: &str,
        text: &str,
        now: u64,
    ) -> Result<serde_json::Value, CoreError> {
        let handle = self.hosted_handle()?;
        let client_id = self.hosted_client_id(conversation_id, text, now)?;
        let deadline = tokio::time::Instant::now() + handle.timeouts().send;
        loop {
            let attempt = tokio::time::timeout_at(
                deadline,
                handle.call(
                    "send",
                    serde_json::json!({
                        "conversation_id": conversation_id,
                        "client_id": client_id,
                        "text": text,
                    }),
                ),
            )
            .await
            .unwrap_or(Err(HostedError::Timeout));
            match attempt {
                Ok(result) => {
                    self.forget_unacknowledged(&client_id);
                    let id = result
                        .get("id")
                        .and_then(serde_json::Value::as_str)
                        .unwrap_or(&client_id)
                        .to_owned();
                    return Ok(serde_json::json!({
                        "id": id,
                        "delivery": "stored",
                        "conversation": hosted_conversation_id(conversation_id),
                        "sequence": result.get("sequence").cloned().unwrap_or(serde_json::Value::Null),
                        "duplicate": result.get("duplicate").cloned().unwrap_or(serde_json::Value::Bool(false)),
                    }));
                }
                Err(HostedError::Server(error)) => {
                    self.forget_unacknowledged(&client_id);
                    return Err(CoreError::Hosted(error));
                }
                Err(
                    HostedError::Disconnected
                    | HostedError::Timeout
                    | HostedError::Stopped
                    | HostedError::Protocol(_),
                ) => {
                    if tokio::time::Instant::now() >= deadline
                        || handle.wait_connected(deadline).await.is_err()
                    {
                        self.remember_unacknowledged(conversation_id, text, &client_id, now);
                        return Err(CoreError::HostedUnavailable);
                    }
                }
            }
        }
    }

    /// Reuse the identifier of an unacknowledged send with the same text,
    /// otherwise mint a fresh random one.
    fn hosted_client_id(
        &self,
        conversation_id: &str,
        text: &str,
        now: u64,
    ) -> Result<String, CoreError> {
        let mut pending = self
            .inner
            .hosted_unacknowledged
            .lock()
            .expect("hosted unacknowledged mutex poisoned");
        pending.retain(|entry| {
            now.saturating_sub(entry.recorded_at) < HOSTED_UNACKNOWLEDGED_TTL_SECONDS
        });
        if let Some(entry) = pending
            .iter()
            .find(|entry| entry.conversation_id == conversation_id && entry.text == text)
        {
            return Ok(entry.client_id.clone());
        }
        let bytes: [u8; 16] = random_bytes()?;
        Ok(format!("d-{}", hex::encode(bytes)))
    }

    fn remember_unacknowledged(
        &self,
        conversation_id: &str,
        text: &str,
        client_id: &str,
        now: u64,
    ) {
        let mut pending = self
            .inner
            .hosted_unacknowledged
            .lock()
            .expect("hosted unacknowledged mutex poisoned");
        if let Some(entry) = pending
            .iter_mut()
            .find(|entry| entry.client_id == client_id)
        {
            entry.recorded_at = now;
            return;
        }
        pending.push(UnacknowledgedSend {
            conversation_id: conversation_id.to_owned(),
            text: text.to_owned(),
            client_id: client_id.to_owned(),
            recorded_at: now,
        });
        while pending.len() > HOSTED_UNACKNOWLEDGED_LIMIT {
            pending.remove(0);
        }
    }

    fn forget_unacknowledged(&self, client_id: &str) {
        self.inner
            .hosted_unacknowledged
            .lock()
            .expect("hosted unacknowledged mutex poisoned")
            .retain(|entry| entry.client_id != client_id);
    }

    async fn hosted_call(
        &self,
        method: &'static str,
        params: serde_json::Value,
    ) -> Result<serde_json::Value, CoreError> {
        self.hosted_handle()?
            .call(method, params)
            .await
            .map_err(hosted_error)
    }

    async fn hosted_conversations(
        &self,
        cursor: Option<String>,
    ) -> Result<serde_json::Value, CoreError> {
        let list = match cursor {
            None => {
                self.hosted_call("list-conversations", serde_json::Value::Null)
                    .await?
            }
            Some(cursor) => {
                if cursor.len() != 34
                    || !matches!(cursor.get(..2), Some("w:" | "c:"))
                    || !cursor.as_bytes()[2..].iter().all(u8::is_ascii_hexdigit)
                {
                    return Err(CoreError::Hosted(omachat_proto::hosted::ServerError::new(
                        omachat_proto::hosted::ErrorCode::InvalidRequest,
                        "invalid conversation cursor",
                    )));
                }
                self.hosted_call(
                    "list-conversations-page",
                    serde_json::json!({"cursor": cursor}),
                )
                .await?
            }
        };
        let conversations = self
            .cache_hosted_conversations(&list)
            .iter()
            .map(|summary| self.hosted_conversation_value(summary))
            .collect::<Vec<_>>();
        let workspaces = list
            .get("workspaces")
            .and_then(serde_json::Value::as_array)
            .cloned()
            .unwrap_or_default();
        // The entire server page is below 16 KiB; the IPC projection fits its
        // 48 KiB budget without dropping rows or invalidating the cursor.
        Ok(
            serde_json::json!({"conversations": conversations, "workspaces": workspaces, "next_cursor": list.get("next_cursor").cloned().unwrap_or(serde_json::Value::Null), "truncated": list.get("next_cursor").is_some_and(serde_json::Value::is_string)}),
        )
    }

    async fn hosted_history(
        &self,
        conversation: &str,
        before_sequence: Option<u64>,
        limit: Option<u32>,
    ) -> Result<serde_json::Value, CoreError> {
        let conversation_id =
            parse_hosted_conversation(conversation).ok_or(CoreError::InvalidConversation)?;
        let result = self
            .hosted_call(
                "history",
                serde_json::json!({
                    "conversation_id": conversation_id,
                    "before_sequence": before_sequence,
                    "limit": limit,
                }),
            )
            .await?;
        let mut messages = Vec::new();
        let mut newest_received = 0;
        for message in result
            .get("messages")
            .and_then(serde_json::Value::as_array)
            .into_iter()
            .flatten()
        {
            if let Some(value) = self.hosted_message_value(message) {
                if value.get("outgoing").and_then(serde_json::Value::as_bool) != Some(true) {
                    newest_received = newest_received.max(
                        message
                            .get("sequence")
                            .and_then(serde_json::Value::as_u64)
                            .unwrap_or_default(),
                    );
                }
                messages.push(value);
            }
        }
        self.mark_hosted_delivered(conversation_id, newest_received)
            .await;
        // History arrives oldest first; keep the newest messages when a page
        // would not fit one IPC line. The client pages again from the oldest
        // sequence it received.
        let (messages, truncated) = fit_ipc_budget(messages, true);
        Ok(serde_json::json!({
            "conversation": conversation,
            "messages": messages,
            "truncated": truncated,
            "next_before_sequence": result.get("next_before_sequence").cloned().unwrap_or(serde_json::Value::Null),
        }))
    }

    async fn hosted_mark_read(
        &self,
        conversation: &str,
        sequence: u64,
    ) -> Result<serde_json::Value, CoreError> {
        let conversation_id =
            parse_hosted_conversation(conversation).ok_or(CoreError::InvalidConversation)?;
        let receipt = self
            .hosted_call(
                "mark-read",
                serde_json::json!({"conversation_id": conversation_id, "sequence": sequence}),
            )
            .await?;
        self.receive_hosted_receipt(&receipt);
        Ok(hosted_receipt_value(&receipt))
    }

    async fn hosted_open_dm(&self, handle: &str) -> Result<serde_json::Value, CoreError> {
        let summary = self
            .hosted_call("open-dm", serde_json::json!({"handle": handle}))
            .await?;
        if let Some(id) = summary
            .get("conversation_id")
            .and_then(serde_json::Value::as_str)
        {
            self.inner
                .hosted_conversations
                .lock()
                .expect("hosted conversations mutex poisoned")
                .insert(id.to_owned(), summary.clone());
        }
        Ok(self.hosted_conversation_value(&summary))
    }

    async fn hosted_claim_handle(&self, handle: &str) -> Result<serde_json::Value, CoreError> {
        let result = self
            .hosted_call("claim-handle", serde_json::json!({"handle": handle}))
            .await?;
        if let Some(claimed) = result.get("handle").and_then(serde_json::Value::as_str)
            && let Some(account) = self
                .inner
                .hosted_account
                .lock()
                .expect("hosted account mutex poisoned")
                .as_mut()
        {
            account.handle = Some(claimed.to_owned());
        }
        self.publish_status_event();
        Ok(result)
    }

    async fn hosted_create_channel(
        &self,
        workspace_id: &str,
        name: &str,
    ) -> Result<serde_json::Value, CoreError> {
        let mut result = self
            .hosted_call(
                "create-channel",
                serde_json::json!({"workspace_id": workspace_id, "name": name}),
            )
            .await?;
        if let Some(id) = result
            .get("conversation_id")
            .and_then(serde_json::Value::as_str)
            .map(hosted_conversation_id)
        {
            result["conversation"] = serde_json::Value::String(id);
        }
        Ok(result)
    }
}

fn hosted_error(error: HostedError) -> CoreError {
    match error {
        HostedError::Server(error) => CoreError::Hosted(error),
        HostedError::Disconnected
        | HostedError::Timeout
        | HostedError::Stopped
        | HostedError::Protocol(_) => CoreError::HostedUnavailable,
    }
}

/// Keep as many values as fit the IPC budget. With `keep_newest`, values
/// are dropped from the front (oldest first); otherwise from the back.
fn fit_ipc_budget(
    values: Vec<serde_json::Value>,
    keep_newest: bool,
) -> (Vec<serde_json::Value>, bool) {
    fit_ipc_budget_limit(values, keep_newest, HOSTED_IPC_BUDGET_BYTES)
}

fn fit_ipc_budget_limit(
    values: Vec<serde_json::Value>,
    keep_newest: bool,
    budget: usize,
) -> (Vec<serde_json::Value>, bool) {
    let mut kept = Vec::with_capacity(values.len());
    let mut used: usize = 0;
    let mut truncated = false;
    let ordered: Box<dyn Iterator<Item = serde_json::Value>> = if keep_newest {
        Box::new(values.into_iter().rev())
    } else {
        Box::new(values.into_iter())
    };
    for value in ordered {
        let size = serde_json::to_vec(&value).map_or(usize::MAX, |bytes| bytes.len() + 1);
        if used.saturating_add(size) > budget {
            truncated = true;
            break;
        }
        used += size;
        kept.push(value);
    }
    if keep_newest {
        kept.reverse();
    }
    (kept, truncated)
}

fn member_display(member: &serde_json::Value) -> String {
    member
        .get("handle")
        .and_then(serde_json::Value::as_str)
        .map(|handle| format!("@{handle}"))
        .or_else(|| {
            member
                .get("display_name")
                .and_then(serde_json::Value::as_str)
                .map(str::to_owned)
        })
        .or_else(|| {
            member
                .get("account_id")
                .and_then(serde_json::Value::as_str)
                .map(str::to_owned)
        })
        .unwrap_or_default()
}

/// IPC shape of a receipt. It names sequences, not message ids, because the
/// server tracks receipts per member and conversation.
fn hosted_receipt_value(receipt: &serde_json::Value) -> serde_json::Value {
    let conversation_id = receipt
        .get("conversation_id")
        .and_then(serde_json::Value::as_str)
        .unwrap_or_default();
    serde_json::json!({
        "conversation": hosted_conversation_id(conversation_id),
        "transport": "hosted",
        "account_id": receipt.get("account_id").cloned().unwrap_or(serde_json::Value::Null),
        "delivered_sequence": receipt.get("delivered_sequence").cloned().unwrap_or(serde_json::Value::Null),
        "read_sequence": receipt.get("read_sequence").cloned().unwrap_or(serde_json::Value::Null),
    })
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

fn confirmation_issue_value(issued: &crate::confirmation::IssuedConfirmation) -> serde_json::Value {
    serde_json::json!({
        "token_path": issued.token_path.display().to_string(),
        "expires_at": issued.expires_at,
        "ttl_seconds": crate::confirmation::CONFIRMATION_TTL_SECONDS,
    })
}

/// Mint a real panic-confirmation token for tests: destructive commands are
/// no longer authorized by a constant string.
#[cfg(test)]
fn minted_panic_token(core: &DaemonCore) -> String {
    let issued = core
        .inner
        .confirmations
        .issue(
            crate::confirmation::ConfirmationAction::PanicErase,
            unix_time().expect("clock"),
        )
        .expect("issue panic token");
    std::fs::read_to_string(issued.token_path)
        .expect("token file")
        .trim()
        .to_owned()
}

fn unix_time() -> Result<u64, CoreError> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .map_err(|_| CoreError::Clock)
}

fn random_bytes<const N: usize>() -> Result<[u8; N], CoreError> {
    let mut bytes = [0_u8; N];
    getrandom::fill(&mut bytes).map_err(|_| CoreError::Random)?;
    Ok(bytes)
}

#[cfg(test)]
mod tests {
    use super::{DaemonCore, PanicLifecycle, PanicState, fit_ipc_budget};
    use crate::{DaemonConfig, EventHub, StorageProviderConfig};
    use std::{sync::Arc, time::Duration};
    use tempfile::tempdir;

    #[test]
    fn ipc_budget_keeps_the_newest_history_and_the_first_conversations() {
        let big = serde_json::json!({"text": "x".repeat(20 * 1024)});
        let values = vec![
            serde_json::json!({"n": 1}),
            big.clone(),
            big.clone(),
            big,
            serde_json::json!({"n": 5}),
        ];
        let (newest, truncated) = fit_ipc_budget(values.clone(), true);
        assert!(truncated);
        assert_eq!(newest.len(), 3);
        assert_eq!(newest[2], serde_json::json!({"n": 5}));
        let (first, truncated) = fit_ipc_budget(values, false);
        assert!(truncated);
        assert_eq!(first.len(), 3);
        assert_eq!(first[0], serde_json::json!({"n": 1}));
        let small = vec![serde_json::json!(1), serde_json::json!(2)];
        assert_eq!(fit_ipc_budget(small.clone(), true), (small, false));
    }

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
        let panic_token = super::minted_panic_token(&core);
        let panic = tokio::spawn(async move { panic_core.panic_erase(&panic_token).await });

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
        let token = super::minted_panic_token(&core);
        assert!(core.panic_erase(&token).await.is_err());
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
