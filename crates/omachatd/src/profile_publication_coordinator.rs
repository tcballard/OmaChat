use std::{
    error::Error,
    fmt,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
};

use omachat_nostr::{auth::RelayAuthSigner, event::SignedEvent};
use omachat_store::SealedStore;
use tokio::{
    sync::{mpsc, oneshot, watch},
    task::JoinHandle,
};

use crate::{
    PendingProfilePublication, ProfilePublicationConfig, ProfilePublicationIntentError,
    ProfilePublicationIntentStore, ProfilePublicationProgress, ProfilePublicationService,
    ProfilePublicationServiceConfig, ProfilePublicationServiceError,
};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ProfilePublicationOutcomeStatus {
    Pending,
    Complete,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProfilePublicationOutcome {
    pub event_id: String,
    pub status: ProfilePublicationOutcomeStatus,
    pub acknowledged_relays: usize,
    pub required_acknowledgements: usize,
}

#[derive(Clone)]
pub struct ProfilePublicationCoordinatorHandle {
    commands: mpsc::Sender<Command>,
    accepting: Arc<AtomicBool>,
    stop: watch::Sender<bool>,
    stopped: watch::Receiver<bool>,
}

impl ProfilePublicationCoordinatorHandle {
    /// Persist and drive one exact signed profile event. Dropping this request
    /// future does not cancel the actor's durable transaction.
    pub async fn publish(
        &self,
        event: &SignedEvent,
        now: u64,
    ) -> Result<ProfilePublicationOutcome, ProfilePublicationCoordinatorError> {
        if !self.accepting.load(Ordering::Acquire) {
            return Err(ProfilePublicationCoordinatorError::Stopped);
        }
        let mut stop = self.stop.subscribe();
        let (response, result) = oneshot::channel();
        tokio::select! {
            biased;
            changed = stop.changed() => {
                let _ = changed;
                return Err(ProfilePublicationCoordinatorError::Stopped);
            }
            sent = self.commands.send(Command::Publish {
                event: event.clone(),
                now,
                response,
            }) => {
                sent.map_err(|_| ProfilePublicationCoordinatorError::Stopped)?;
            }
        }
        tokio::select! {
            biased;
            changed = stop.changed() => {
                let _ = changed;
                Err(ProfilePublicationCoordinatorError::Stopped)
            }
            received = result => {
                received.map_err(|_| ProfilePublicationCoordinatorError::Stopped)?
            }
        }
    }

    /// Resume the exact sealed event and remaining relay set, if present.
    pub async fn resume(
        &self,
        now: u64,
    ) -> Result<Option<ProfilePublicationOutcome>, ProfilePublicationCoordinatorError> {
        if !self.accepting.load(Ordering::Acquire) {
            return Err(ProfilePublicationCoordinatorError::Stopped);
        }
        let mut stop = self.stop.subscribe();
        let (response, result) = oneshot::channel();
        tokio::select! {
            biased;
            changed = stop.changed() => {
                let _ = changed;
                return Err(ProfilePublicationCoordinatorError::Stopped);
            }
            sent = self.commands.send(Command::Resume { now, response }) => {
                sent.map_err(|_| ProfilePublicationCoordinatorError::Stopped)?;
            }
        }
        tokio::select! {
            biased;
            changed = stop.changed() => {
                let _ = changed;
                Err(ProfilePublicationCoordinatorError::Stopped)
            }
            received = result => {
                received.map_err(|_| ProfilePublicationCoordinatorError::Stopped)?
            }
        }
    }

    /// Stop accepting work and wait until the coordinator and every relay actor
    /// it owns have terminated.
    pub async fn quiesce(&self) {
        self.accepting.store(false, Ordering::Release);
        self.stop.send_replace(true);
        let mut stopped = self.stopped.clone();
        while !*stopped.borrow() {
            if stopped.changed().await.is_err() {
                break;
            }
        }
    }
}

/// Bounded actor owning the sealed profile transaction and its live relay pool.
pub struct ProfilePublicationCoordinator {
    handle: ProfilePublicationCoordinatorHandle,
    task: Option<JoinHandle<Result<(), ProfilePublicationCoordinatorError>>>,
}

impl ProfilePublicationCoordinator {
    pub fn spawn(
        store: Arc<SealedStore>,
        config: &ProfilePublicationConfig,
        auth_signer: RelayAuthSigner,
        service_config: ProfilePublicationServiceConfig,
    ) -> Result<Self, ProfilePublicationCoordinatorError> {
        let runtime = Runtime::new(store, config, auth_signer, service_config)?;
        let (commands, receiver) = mpsc::channel(8);
        let accepting = Arc::new(AtomicBool::new(true));
        let (stop, stop_receiver) = watch::channel(false);
        let (stopped_sender, stopped) = watch::channel(false);
        let handle = ProfilePublicationCoordinatorHandle {
            commands,
            accepting: Arc::clone(&accepting),
            stop,
            stopped,
        };
        let task = tokio::spawn(run(
            runtime,
            receiver,
            stop_receiver,
            accepting,
            stopped_sender,
        ));
        Ok(Self {
            handle,
            task: Some(task),
        })
    }

    #[must_use]
    pub fn handle(&self) -> ProfilePublicationCoordinatorHandle {
        self.handle.clone()
    }

    pub async fn shutdown(mut self) -> Result<(), ProfilePublicationCoordinatorError> {
        self.handle.quiesce().await;
        let result = self
            .task
            .as_mut()
            .expect("profile coordinator task remains owned")
            .await
            .map_err(|_| ProfilePublicationCoordinatorError::Task)?;
        self.task.take();
        result
    }
}

impl Drop for ProfilePublicationCoordinator {
    fn drop(&mut self) {
        if let Some(task) = &self.task {
            task.abort();
        }
    }
}

enum Command {
    Publish {
        event: SignedEvent,
        now: u64,
        response:
            oneshot::Sender<Result<ProfilePublicationOutcome, ProfilePublicationCoordinatorError>>,
    },
    Resume {
        now: u64,
        response: oneshot::Sender<
            Result<Option<ProfilePublicationOutcome>, ProfilePublicationCoordinatorError>,
        >,
    },
}

struct Runtime {
    store: Arc<SealedStore>,
    relay_urls: Vec<String>,
    required_acknowledgements: usize,
    expected_public_key: [u8; 32],
    auth_signer: RelayAuthSigner,
    service_config: ProfilePublicationServiceConfig,
    service: Option<ProfilePublicationService>,
}

impl Runtime {
    fn new(
        store: Arc<SealedStore>,
        config: &ProfilePublicationConfig,
        auth_signer: RelayAuthSigner,
        service_config: ProfilePublicationServiceConfig,
    ) -> Result<Self, ProfilePublicationCoordinatorError> {
        let relay_urls = config
            .canonical_relays()
            .map_err(|_| ProfilePublicationCoordinatorError::InvalidConfig)?;
        let expected_public_key = *auth_signer.public_key();
        Ok(Self {
            store,
            relay_urls,
            required_acknowledgements: config.required_acknowledgements,
            expected_public_key,
            auth_signer,
            service_config,
            service: None,
        })
    }

    async fn publish(
        &mut self,
        event: &SignedEvent,
        now: u64,
    ) -> Result<ProfilePublicationOutcome, ProfilePublicationCoordinatorError> {
        let pending = ProfilePublicationIntentStore::new(self.store.as_ref()).prepare(
            event,
            &self.relay_urls,
            self.required_acknowledgements,
            &self.expected_public_key,
            now,
            &Default::default(),
        )?;
        self.drive(pending, now).await
    }

    async fn resume(
        &mut self,
        now: u64,
    ) -> Result<Option<ProfilePublicationOutcome>, ProfilePublicationCoordinatorError> {
        let Some(pending) = ProfilePublicationIntentStore::new(self.store.as_ref()).load(
            &self.expected_public_key,
            now,
            &Default::default(),
        )?
        else {
            return Ok(None);
        };
        self.verify_policy(&pending)?;
        self.drive(pending, now).await.map(Some)
    }

    async fn drive(
        &mut self,
        pending: PendingProfilePublication,
        now: u64,
    ) -> Result<ProfilePublicationOutcome, ProfilePublicationCoordinatorError> {
        self.verify_policy(&pending)?;
        if self.service.is_none() {
            self.service = Some(ProfilePublicationService::spawn(
                pending.relay_urls(),
                self.auth_signer.clone(),
                self.service_config.clone(),
            )?);
        }
        let result = self
            .service
            .as_ref()
            .expect("profile publication service is owned")
            .handle()
            .publish(&pending)
            .await?;
        let accepted = result
            .outcomes
            .iter()
            .filter(|outcome| outcome.result.is_ok())
            .map(|outcome| outcome.relay_index)
            .collect::<Vec<_>>();
        let event_id = pending.event().id.clone();
        let progress = ProfilePublicationIntentStore::new(self.store.as_ref()).acknowledge(
            &event_id,
            &accepted,
            &self.expected_public_key,
            now,
            &Default::default(),
        )?;
        Ok(self.outcome(event_id, progress))
    }

    fn verify_policy(
        &self,
        pending: &PendingProfilePublication,
    ) -> Result<(), ProfilePublicationCoordinatorError> {
        if pending.relay_urls() != self.relay_urls
            || pending.required_acknowledgements() != self.required_acknowledgements
        {
            return Err(ProfilePublicationCoordinatorError::PolicyMismatch);
        }
        Ok(())
    }

    fn outcome(
        &self,
        event_id: String,
        progress: ProfilePublicationProgress,
    ) -> ProfilePublicationOutcome {
        match progress {
            ProfilePublicationProgress::Pending(pending) => ProfilePublicationOutcome {
                event_id,
                status: ProfilePublicationOutcomeStatus::Pending,
                acknowledged_relays: pending.acknowledged_relay_indices().len(),
                required_acknowledgements: self.required_acknowledgements,
            },
            ProfilePublicationProgress::Complete => ProfilePublicationOutcome {
                event_id,
                status: ProfilePublicationOutcomeStatus::Complete,
                acknowledged_relays: self.required_acknowledgements,
                required_acknowledgements: self.required_acknowledgements,
            },
        }
    }

    async fn shutdown(mut self) -> Result<(), ProfilePublicationCoordinatorError> {
        if let Some(service) = self.service.take() {
            service.shutdown().await?;
        }
        Ok(())
    }
}

async fn run(
    mut runtime: Runtime,
    mut commands: mpsc::Receiver<Command>,
    mut stop: watch::Receiver<bool>,
    accepting: Arc<AtomicBool>,
    stopped: watch::Sender<bool>,
) -> Result<(), ProfilePublicationCoordinatorError> {
    run_until_stopped(&mut runtime, &mut commands, &mut stop).await;
    accepting.store(false, Ordering::Release);
    commands.close();
    while commands.try_recv().is_ok() {}
    let result = runtime.shutdown().await;
    stopped.send_replace(true);
    result
}

async fn run_until_stopped(
    runtime: &mut Runtime,
    commands: &mut mpsc::Receiver<Command>,
    stop: &mut watch::Receiver<bool>,
) {
    loop {
        tokio::select! {
            biased;
            _ = wait_for_stop(stop) => return,
            command = commands.recv() => {
                let Some(command) = command else { return };
                if run_command(runtime, command, stop).await {
                    return;
                }
            }
        }
    }
}

async fn run_command(
    runtime: &mut Runtime,
    command: Command,
    stop: &mut watch::Receiver<bool>,
) -> bool {
    match command {
        Command::Publish {
            event,
            now,
            response,
        } => {
            tokio::select! {
                biased;
                _ = wait_for_stop(stop) => {
                    let _ = response.send(Err(ProfilePublicationCoordinatorError::Stopped));
                    true
                }
                result = runtime.publish(&event, now) => {
                    let _ = response.send(result);
                    false
                }
            }
        }
        Command::Resume { now, response } => {
            tokio::select! {
                biased;
                _ = wait_for_stop(stop) => {
                    let _ = response.send(Err(ProfilePublicationCoordinatorError::Stopped));
                    true
                }
                result = runtime.resume(now) => {
                    let _ = response.send(result);
                    false
                }
            }
        }
    }
}

async fn wait_for_stop(stop: &mut watch::Receiver<bool>) {
    loop {
        if *stop.borrow() {
            return;
        }
        if stop.changed().await.is_err() {
            return;
        }
    }
}

#[derive(Debug)]
pub enum ProfilePublicationCoordinatorError {
    InvalidConfig,
    PolicyMismatch,
    Intent(ProfilePublicationIntentError),
    Service(ProfilePublicationServiceError),
    Stopped,
    Task,
}

impl fmt::Display for ProfilePublicationCoordinatorError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidConfig => formatter.write_str("profile publication config is invalid"),
            Self::PolicyMismatch => formatter
                .write_str("sealed profile publication policy does not match daemon config"),
            Self::Intent(error) => write!(formatter, "profile publication intent failed: {error}"),
            Self::Service(error) => {
                write!(formatter, "profile publication service failed: {error}")
            }
            Self::Stopped => formatter.write_str("profile publication coordinator is stopped"),
            Self::Task => formatter.write_str("profile publication coordinator task failed"),
        }
    }
}

impl Error for ProfilePublicationCoordinatorError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Intent(error) => Some(error),
            Self::Service(error) => Some(error),
            Self::InvalidConfig | Self::PolicyMismatch | Self::Stopped | Self::Task => None,
        }
    }
}

impl From<ProfilePublicationIntentError> for ProfilePublicationCoordinatorError {
    fn from(error: ProfilePublicationIntentError) -> Self {
        Self::Intent(error)
    }
}

impl From<ProfilePublicationServiceError> for ProfilePublicationCoordinatorError {
    fn from(error: ProfilePublicationServiceError) -> Self {
        Self::Service(error)
    }
}
