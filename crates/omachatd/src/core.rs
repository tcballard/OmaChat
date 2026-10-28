use crate::{
    CoreError, DaemonConfig,
    hosted_service::{
        DeviceSigner, HostedAccount, HostedError, HostedEvent, HostedHandle, HostedService,
        HostedServiceConfig, HostedState, HostedTimeouts,
    },
    ipc_server::{EventHub, RequestHandler},
};
use omachat_crypto::IdentitySecrets;
use omachat_proto::ipc::{Command, ErrorBody, ErrorCode, Event, Request, ResponseOutcome, VERSION};
use omachat_store::{IdentityVault, SealedStore};
use serde::Serialize;
use std::{
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
    identity: Mutex<Option<IdentitySecrets>>,
    storage_transaction: Mutex<()>,
    operations: tokio::sync::RwLock<()>,
    panic: PanicLifecycle,
    hosted: Mutex<Option<HostedHandle>>,
    /// Last account the hosted server authenticated; kept across
    /// reconnects so status stays truthful while disconnected.
    hosted_account: Mutex<Option<HostedAccount>>,
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
        Ok(Self {
            inner: Arc::new(CoreInner {
                store,
                identity: Mutex::new(Some(identity)),
                storage_transaction: Mutex::new(()),
                operations: tokio::sync::RwLock::new(()),
                panic: PanicLifecycle::default(),
                hosted: Mutex::new(None),
                hosted_account: Mutex::new(None),
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
            Command::RequestPanicConfirmation => {
                let issued = self.inner.confirmations.issue(
                    crate::confirmation::ConfirmationAction::PanicErase,
                    unix_time()?,
                )?;
                Ok(confirmation_issue_value(&issued))
            }
            Command::HostedClaimHandle { handle } => self.hosted_claim_handle(&handle).await,
            Command::HostedResolveHandle { handle } => {
                self.hosted_call("resolve-handle", serde_json::json!({"handle": handle}))
                    .await
            }
            Command::Subscribe { topics } => {
                Ok(serde_json::json!({"topics": topics, "status": self.status_value()?}))
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
            serde_json::json!({"storage_provider": self.inner.store.status().provider, "fingerprint": public.fingerprint_hex, "device_public_key": hex::encode(public.signing_public_key), "hosted": self.hosted_status()}),
        )
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
            }
            // The thin server does not emit chat events. Ignore anything else
            // so a future relay frame cannot crash this process.
            HostedEvent::Server { .. } => {}
        }
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
