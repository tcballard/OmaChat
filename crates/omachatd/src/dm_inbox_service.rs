use std::{
    error::Error,
    fmt,
    time::{SystemTime, UNIX_EPOCH},
};

use omachat_nostr::{
    auth::RelayAuthSigner,
    dm_inbox_runtime::{
        AuthenticatedDmInboxRuntime, DmInboxRuntimeConfig, DmInboxRuntimeError, DmInboxRuntimeEvent,
    },
    relay::{RelayConfig, RelayError, RelayRoute},
};
use tokio::{
    sync::{mpsc, watch},
    task::JoinHandle,
};

#[derive(Clone)]
pub struct DmInboxHandle {
    shutdown: watch::Sender<bool>,
    terminated: watch::Receiver<bool>,
}

impl DmInboxHandle {
    /// Stop accepting or decrypting events and wait until relay actors have
    /// joined and the runtime-owned key copy has been dropped.
    pub async fn quiesce(&self) {
        self.shutdown.send_replace(true);
        let mut terminated = self.terminated.clone();
        while !*terminated.borrow() {
            if terminated.changed().await.is_err() {
                break;
            }
        }
    }
}

pub struct DmInboxService {
    handle: DmInboxHandle,
    task: Option<JoinHandle<Result<(), DmInboxServiceError>>>,
}

impl DmInboxService {
    pub async fn spawn(
        urls: &[String],
        auth_signer: RelayAuthSigner,
        recipient_secret_key: [u8; 32],
        blocked_authors: &[String],
        inbound: mpsc::Sender<DmInboxRuntimeEvent>,
    ) -> Result<Self, DmInboxServiceError> {
        let relay_configs = urls
            .iter()
            .map(|url| RelayConfig::new(url.clone(), RelayRoute::Direct))
            .collect();
        Self::spawn_with_config(
            relay_configs,
            auth_signer,
            recipient_secret_key,
            blocked_authors,
            DmInboxRuntimeConfig::default(),
            inbound,
        )
        .await
    }

    pub async fn spawn_with_config(
        relay_configs: Vec<RelayConfig>,
        auth_signer: RelayAuthSigner,
        recipient_secret_key: [u8; 32],
        blocked_authors: &[String],
        runtime_config: DmInboxRuntimeConfig,
        inbound: mpsc::Sender<DmInboxRuntimeEvent>,
    ) -> Result<Self, DmInboxServiceError> {
        let now = unix_time()?;
        let mut runtime = AuthenticatedDmInboxRuntime::connect(
            relay_configs,
            auth_signer,
            recipient_secret_key,
            runtime_config,
            now,
        )
        .await
        .map_err(DmInboxServiceError::Runtime)?;

        for author in blocked_authors {
            if let Err(error) = runtime.block_author(author) {
                let _ = runtime.shutdown().await;
                return Err(DmInboxServiceError::Runtime(error));
            }
        }

        let (shutdown, shutdown_receiver) = watch::channel(false);
        let (terminated_sender, terminated) = watch::channel(false);
        let task = tokio::spawn(run_service(
            runtime,
            inbound,
            shutdown_receiver,
            terminated_sender,
        ));
        Ok(Self {
            handle: DmInboxHandle {
                shutdown,
                terminated,
            },
            task: Some(task),
        })
    }

    #[must_use]
    pub fn handle(&self) -> DmInboxHandle {
        self.handle.clone()
    }

    pub async fn shutdown(mut self) -> Result<(), DmInboxServiceError> {
        self.handle.quiesce().await;
        let task = self.task.take().expect("inbox service task exists");
        task.await.map_err(|_| DmInboxServiceError::Task)?
    }
}

impl Drop for DmInboxService {
    fn drop(&mut self) {
        self.handle.shutdown.send_replace(true);
        if let Some(task) = self.task.take() {
            task.abort();
        }
    }
}

async fn run_service(
    mut runtime: AuthenticatedDmInboxRuntime,
    inbound: mpsc::Sender<DmInboxRuntimeEvent>,
    mut shutdown: watch::Receiver<bool>,
    terminated: watch::Sender<bool>,
) -> Result<(), DmInboxServiceError> {
    let run_result = run_until_shutdown(&mut runtime, inbound, &mut shutdown).await;
    let relay_shutdown = runtime.shutdown().await;
    terminated.send_replace(true);

    run_result?;
    if let Some((relay_index, error)) = relay_shutdown
        .into_iter()
        .enumerate()
        .find_map(|(relay_index, result)| result.err().map(|error| (relay_index, error)))
    {
        return Err(DmInboxServiceError::RelayShutdown { relay_index, error });
    }
    Ok(())
}

async fn run_until_shutdown(
    runtime: &mut AuthenticatedDmInboxRuntime,
    inbound: mpsc::Sender<DmInboxRuntimeEvent>,
    shutdown: &mut watch::Receiver<bool>,
) -> Result<(), DmInboxServiceError> {
    'service: loop {
        if *shutdown.borrow() {
            return Ok(());
        }
        let event = tokio::select! {
            biased;
            changed = shutdown.changed() => {
                if changed.is_err() || *shutdown.borrow() {
                    return Ok(());
                }
                continue;
            }
            event = runtime.next(unix_time()?) => {
                event.map_err(DmInboxServiceError::Runtime)?
            }
        };

        tokio::select! {
            biased;
            changed = shutdown.changed() => {
                if changed.is_err() || *shutdown.borrow() {
                    break 'service;
                }
            }
            result = inbound.send(event) => {
                if result.is_err() {
                    break 'service;
                }
            }
        }
    }
    Ok(())
}

fn unix_time() -> Result<u64, DmInboxServiceError> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .map_err(|_| DmInboxServiceError::Clock)
}

#[derive(Debug)]
pub enum DmInboxServiceError {
    Runtime(DmInboxRuntimeError),
    RelayShutdown {
        relay_index: usize,
        error: RelayError,
    },
    Clock,
    Task,
}

impl fmt::Display for DmInboxServiceError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Runtime(error) => write!(formatter, "authenticated inbox failed: {error}"),
            Self::RelayShutdown { relay_index, error } => {
                write!(
                    formatter,
                    "inbox relay {relay_index} shutdown failed: {error}"
                )
            }
            Self::Clock => formatter.write_str("system clock is before the Unix epoch"),
            Self::Task => formatter.write_str("authenticated inbox task failed"),
        }
    }
}

impl Error for DmInboxServiceError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Runtime(error) => Some(error),
            Self::RelayShutdown { error, .. } => Some(error),
            Self::Clock | Self::Task => None,
        }
    }
}
