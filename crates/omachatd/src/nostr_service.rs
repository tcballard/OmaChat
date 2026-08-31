use omachat_nostr::{
    event::SignedEvent,
    pool::{PoolNotification, PoolPublishResult, RelayPool, RelayPoolConfig, RelayPoolError},
    relay::{RelayConfig, RelayRoute},
};
use serde_json::Value;
use std::{error::Error, fmt, time::Duration};
use tokio::{
    sync::{mpsc, oneshot},
    task::JoinHandle,
    time::timeout,
};

const COMMAND_CAPACITY: usize = 64;
const INBOUND_POLL: Duration = Duration::from_millis(50);

enum Command {
    Publish(
        SignedEvent,
        oneshot::Sender<Result<PoolPublishResult, RelayPoolError>>,
    ),
    Subscribe(
        String,
        Vec<Value>,
        oneshot::Sender<Vec<Result<(), omachat_nostr::relay::RelayError>>>,
    ),
    Shutdown(oneshot::Sender<()>),
}

#[derive(Clone)]
pub struct NostrHandle {
    commands: mpsc::Sender<Command>,
}
impl NostrHandle {
    pub async fn publish(&self, event: SignedEvent) -> Result<PoolPublishResult, RelayPoolError> {
        let (sender, receiver) = oneshot::channel();
        self.commands
            .send(Command::Publish(event, sender))
            .await
            .map_err(|_| RelayPoolError::InvalidConfig("relay service stopped"))?;
        receiver
            .await
            .map_err(|_| RelayPoolError::InvalidConfig("relay service stopped"))?
    }
    pub async fn subscribe(
        &self,
        id: String,
        filters: Vec<Value>,
    ) -> Result<(), NostrServiceError> {
        let (sender, receiver) = oneshot::channel();
        self.commands
            .send(Command::Subscribe(id, filters, sender))
            .await
            .map_err(|_| NostrServiceError::Stopped)?;
        let results = receiver.await.map_err(|_| NostrServiceError::Stopped)?;
        if results.iter().any(Result::is_ok) {
            Ok(())
        } else {
            Err(NostrServiceError::Subscription)
        }
    }
}

pub struct NostrService {
    handle: NostrHandle,
    task: JoinHandle<Result<(), RelayPoolError>>,
}
impl NostrService {
    pub fn spawn(
        urls: &[String],
        inbound: mpsc::Sender<PoolNotification>,
    ) -> Result<Self, RelayPoolError> {
        let configs = urls
            .iter()
            .cloned()
            .map(|url| RelayConfig::new(url, RelayRoute::Direct))
            .collect();
        let pool = RelayPool::spawn(configs, RelayPoolConfig::default())?;
        let (sender, receiver) = mpsc::channel(COMMAND_CAPACITY);
        let handle = NostrHandle { commands: sender };
        let task = tokio::spawn(run(pool, receiver, inbound));
        Ok(Self { handle, task })
    }
    #[must_use]
    pub fn handle(&self) -> NostrHandle {
        self.handle.clone()
    }
    pub async fn shutdown(self) -> Result<(), NostrServiceError> {
        let (sender, receiver) = oneshot::channel();
        self.handle
            .commands
            .send(Command::Shutdown(sender))
            .await
            .map_err(|_| NostrServiceError::Stopped)?;
        let _ = receiver.await;
        self.task
            .await
            .map_err(|_| NostrServiceError::Task)?
            .map_err(NostrServiceError::Pool)
    }
}

async fn run(
    mut pool: RelayPool,
    mut commands: mpsc::Receiver<Command>,
    inbound: mpsc::Sender<PoolNotification>,
) -> Result<(), RelayPoolError> {
    loop {
        while let Ok(command) = commands.try_recv() {
            match command {
                Command::Publish(event, response) => {
                    let _ = response.send(pool.publish(event).await);
                }
                Command::Subscribe(id, filters, response) => {
                    let _ = response.send(pool.subscribe(id, filters).await);
                }
                Command::Shutdown(response) => {
                    let _ = response.send(());
                    return pool
                        .shutdown()
                        .await
                        .into_iter()
                        .find_map(Result::err)
                        .map_or(Ok(()), |error| Err(error.into()));
                }
            }
        }
        if commands.is_closed() {
            return pool
                .shutdown()
                .await
                .into_iter()
                .find_map(Result::err)
                .map_or(Ok(()), |error| Err(error.into()));
        }
        if let Ok(Some(notification)) = timeout(INBOUND_POLL, pool.next_notification()).await
            && inbound.send(notification).await.is_err()
        {
            return Ok(());
        }
        tokio::task::yield_now().await;
    }
}

#[derive(Debug)]
pub enum NostrServiceError {
    Pool(RelayPoolError),
    Stopped,
    Subscription,
    Task,
}
impl fmt::Display for NostrServiceError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Nostr service error: {self:?}")
    }
}
impl Error for NostrServiceError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Pool(e) => Some(e),
            _ => None,
        }
    }
}
