use std::{error::Error, fmt, time::Duration};

use omachat_nostr::{
    auth::RelayAuthSigner,
    dm_delivery::{AuthenticatedDmDelivery, DmDeliveryError},
    dm_routed_publish::RoutedDmPublishPlan,
    pool::PoolPublishResult,
    relay::{RelayError, RelayRoute},
};
use tokio::{
    sync::{mpsc, oneshot, watch},
    task::JoinHandle,
};

const COMMAND_CAPACITY: usize = 64;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DmDeliveryServiceConfig {
    pub authentication_timeout: Duration,
    pub transport_route: RelayRoute,
}

impl Default for DmDeliveryServiceConfig {
    fn default() -> Self {
        Self {
            authentication_timeout: Duration::from_secs(10),
            transport_route: RelayRoute::Direct,
        }
    }
}

enum Command {
    Publish {
        plan: RoutedDmPublishPlan,
        response: oneshot::Sender<Result<PoolPublishResult, DmDeliveryServiceError>>,
    },
}

#[derive(Clone)]
pub struct DmDeliveryHandle {
    commands: mpsc::Sender<Command>,
    shutdown: watch::Sender<bool>,
    terminated: watch::Receiver<bool>,
}

impl DmDeliveryHandle {
    pub async fn publish(
        &self,
        plan: RoutedDmPublishPlan,
    ) -> Result<PoolPublishResult, DmDeliveryServiceError> {
        let mut shutdown = self.shutdown.subscribe();
        if *shutdown.borrow() || *self.terminated.borrow() {
            return Err(DmDeliveryServiceError::Stopped);
        }
        let (response, result) = oneshot::channel();
        tokio::select! {
            biased;
            changed = shutdown.changed() => {
                let _ = changed;
                return Err(DmDeliveryServiceError::Stopped);
            }
            sent = self.commands.send(Command::Publish { plan, response }) => {
                sent.map_err(|_| DmDeliveryServiceError::Stopped)?;
            }
        }
        tokio::select! {
            biased;
            changed = shutdown.changed() => {
                let _ = changed;
                Err(DmDeliveryServiceError::Stopped)
            }
            received = result => {
                received.map_err(|_| DmDeliveryServiceError::Stopped)?
            }
        }
    }

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

pub struct DmDeliveryService {
    handle: DmDeliveryHandle,
    task: Option<JoinHandle<()>>,
}

impl DmDeliveryService {
    pub fn spawn(
        auth_signer: RelayAuthSigner,
        config: DmDeliveryServiceConfig,
    ) -> Result<Self, DmDeliveryServiceError> {
        if config.authentication_timeout.is_zero() {
            return Err(DmDeliveryServiceError::InvalidConfig);
        }
        let (shutdown, shutdown_receiver) = watch::channel(false);
        let (terminated_sender, terminated) = watch::channel(false);
        let (commands, command_receiver) = mpsc::channel(COMMAND_CAPACITY);
        let task = tokio::spawn(run_service(
            auth_signer,
            config,
            command_receiver,
            shutdown_receiver,
            terminated_sender,
        ));
        Ok(Self {
            handle: DmDeliveryHandle {
                commands,
                shutdown,
                terminated,
            },
            task: Some(task),
        })
    }

    #[must_use]
    pub fn handle(&self) -> DmDeliveryHandle {
        self.handle.clone()
    }

    pub async fn shutdown(mut self) -> Result<(), DmDeliveryServiceError> {
        self.handle.quiesce().await;
        let task = self.task.take().expect("delivery service task exists");
        task.await.map_err(|_| DmDeliveryServiceError::Task)
    }
}

impl Drop for DmDeliveryService {
    fn drop(&mut self) {
        self.handle.shutdown.send_replace(true);
        if let Some(task) = self.task.take() {
            task.abort();
        }
    }
}

async fn run_service(
    auth_signer: RelayAuthSigner,
    config: DmDeliveryServiceConfig,
    mut commands: mpsc::Receiver<Command>,
    mut shutdown: watch::Receiver<bool>,
    terminated: watch::Sender<bool>,
) {
    loop {
        if *shutdown.borrow() {
            break;
        }
        let command = tokio::select! {
            biased;
            changed = shutdown.changed() => {
                let _ = changed;
                break;
            }
            command = commands.recv() => command,
        };
        let Some(Command::Publish { plan, response }) = command else {
            break;
        };
        let result = execute_delivery(plan, auth_signer.clone(), &config, shutdown.clone()).await;
        let stopped = matches!(result, Err(DmDeliveryServiceError::Stopped));
        let _ = response.send(result);
        if stopped {
            break;
        }
    }
    terminated.send_replace(true);
}

async fn execute_delivery(
    plan: RoutedDmPublishPlan,
    auth_signer: RelayAuthSigner,
    config: &DmDeliveryServiceConfig,
    mut shutdown: watch::Receiver<bool>,
) -> Result<PoolPublishResult, DmDeliveryServiceError> {
    let mut delivery =
        AuthenticatedDmDelivery::spawn(plan, config.transport_route.clone(), auth_signer)?;
    let mut result = tokio::select! {
        biased;
        changed = shutdown.changed() => {
            let _ = changed;
            Err(DmDeliveryServiceError::Stopped)
        }
        authenticated = delivery.wait_until_authenticated(config.authentication_timeout) => {
            authenticated.map_err(DmDeliveryServiceError::Delivery)
        }
    }
    .map(|()| None);

    if matches!(result, Ok(None)) {
        result = tokio::select! {
            biased;
            changed = shutdown.changed() => {
                let _ = changed;
                Err(DmDeliveryServiceError::Stopped)
            }
            published = delivery.publish() => {
                published
                    .map(Some)
                    .map_err(DmDeliveryServiceError::Delivery)
            }
        };
    }

    let relay_shutdown = delivery.shutdown().await;
    let published = result?;
    if let Some((relay_index, error)) = relay_shutdown
        .into_iter()
        .enumerate()
        .find_map(|(relay_index, result)| result.err().map(|error| (relay_index, error)))
    {
        return Err(DmDeliveryServiceError::RelayShutdown { relay_index, error });
    }
    published.ok_or(DmDeliveryServiceError::Stopped)
}

#[derive(Debug)]
pub enum DmDeliveryServiceError {
    InvalidConfig,
    Delivery(DmDeliveryError),
    RelayShutdown {
        relay_index: usize,
        error: RelayError,
    },
    Stopped,
    Task,
}

impl fmt::Display for DmDeliveryServiceError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidConfig => formatter.write_str("invalid DM delivery service configuration"),
            Self::Delivery(error) => write!(formatter, "recipient DM delivery failed: {error}"),
            Self::RelayShutdown { relay_index, error } => {
                write!(
                    formatter,
                    "recipient relay {relay_index} shutdown failed: {error}"
                )
            }
            Self::Stopped => formatter.write_str("DM delivery service stopped"),
            Self::Task => formatter.write_str("DM delivery service task failed"),
        }
    }
}

impl Error for DmDeliveryServiceError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Delivery(error) => Some(error),
            Self::RelayShutdown { error, .. } => Some(error),
            Self::InvalidConfig | Self::Stopped | Self::Task => None,
        }
    }
}

impl From<DmDeliveryError> for DmDeliveryServiceError {
    fn from(error: DmDeliveryError) -> Self {
        Self::Delivery(error)
    }
}
