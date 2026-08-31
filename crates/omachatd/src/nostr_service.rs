use omachat_nostr::{
    event::SignedEvent,
    pool::{PoolNotification, PoolPublishResult, RelayPool, RelayPoolConfig, RelayPoolError},
    relay::{RelayConfig, RelayRoute},
};
use serde_json::Value;
use std::{
    error::Error,
    fmt,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    time::Duration,
};
use tokio::{
    sync::{mpsc, oneshot, watch},
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
}

#[derive(Clone)]
pub struct NostrHandle {
    commands: mpsc::Sender<Command>,
    accepting: Arc<AtomicBool>,
    stop: watch::Sender<bool>,
    stopped: watch::Receiver<bool>,
}
impl NostrHandle {
    pub async fn publish(&self, event: SignedEvent) -> Result<PoolPublishResult, RelayPoolError> {
        if !self.accepting.load(Ordering::Acquire) {
            return Err(stopped_pool_error());
        }
        let (sender, receiver) = oneshot::channel();
        self.commands
            .send(Command::Publish(event, sender))
            .await
            .map_err(|_| stopped_pool_error())?;
        receiver.await.map_err(|_| stopped_pool_error())?
    }
    pub async fn subscribe(
        &self,
        id: String,
        filters: Vec<Value>,
    ) -> Result<(), NostrServiceError> {
        if !self.accepting.load(Ordering::Acquire) {
            return Err(NostrServiceError::Stopped);
        }
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

    /// Stop accepting work, cancel the active relay operation, discard queued
    /// work, and wait until every relay connection has been shut down.
    pub async fn quiesce(&self) {
        self.accepting.store(false, Ordering::Release);
        let _ = self.stop.send(true);
        let mut stopped = self.stopped.clone();
        loop {
            if *stopped.borrow() {
                return;
            }
            if stopped.changed().await.is_err() {
                // The actor dropped its sole completion sender, so it can no
                // longer own or publish through the relay pool.
                return;
            }
        }
    }
}

pub struct NostrService {
    handle: NostrHandle,
    task: Option<JoinHandle<Result<(), RelayPoolError>>>,
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
        let accepting = Arc::new(AtomicBool::new(true));
        let (stop, stop_receiver) = watch::channel(false);
        let (stopped_sender, stopped) = watch::channel(false);
        let handle = NostrHandle {
            commands: sender,
            accepting: Arc::clone(&accepting),
            stop,
            stopped,
        };
        let task = tokio::spawn(run(
            pool,
            receiver,
            inbound,
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
    pub fn handle(&self) -> NostrHandle {
        self.handle.clone()
    }
    pub async fn shutdown(mut self) -> Result<(), NostrServiceError> {
        self.handle.quiesce().await;
        let result = self
            .task
            .as_mut()
            .expect("Nostr service task remains owned")
            .await
            .map_err(|_| NostrServiceError::Task)?;
        self.task.take();
        result.map_err(NostrServiceError::Pool)
    }
}

impl Drop for NostrService {
    fn drop(&mut self) {
        // Dropping a Tokio JoinHandle detaches its task. Abort first so a
        // cancelled shutdown future cannot strand the service and its relay
        // actors in the background.
        if let Some(task) = &self.task {
            task.abort();
        }
    }
}

async fn run(
    mut pool: RelayPool,
    mut commands: mpsc::Receiver<Command>,
    inbound: mpsc::Sender<PoolNotification>,
    mut stop: watch::Receiver<bool>,
    accepting: Arc<AtomicBool>,
    stopped: watch::Sender<bool>,
) -> Result<(), RelayPoolError> {
    run_until_stopped(&mut pool, &mut commands, &inbound, &mut stop).await;

    // Closing and draining the command queue drops every response sender. No
    // queued publish is forwarded while the relay pool is shutting down.
    accepting.store(false, Ordering::Release);
    commands.close();
    while commands.try_recv().is_ok() {}
    let result = pool
        .shutdown()
        .await
        .into_iter()
        .find_map(Result::err)
        .map_or(Ok(()), |error| Err(error.into()));
    let _ = stopped.send(true);
    result
}

async fn run_until_stopped(
    pool: &mut RelayPool,
    commands: &mut mpsc::Receiver<Command>,
    inbound: &mpsc::Sender<PoolNotification>,
    stop: &mut watch::Receiver<bool>,
) {
    loop {
        tokio::select! {
            biased;
            _ = wait_for_stop(stop) => return,
            command = commands.recv() => {
                let Some(command) = command else { return };
                if run_command(pool, command, stop).await {
                    return;
                }
            }
            notification = timeout(INBOUND_POLL, pool.next_notification()) => {
                if let Ok(Some(notification)) = notification {
                    tokio::select! {
                        biased;
                        _ = wait_for_stop(stop) => return,
                        result = inbound.send(notification) => {
                            if result.is_err() {
                                return;
                            }
                        }
                    }
                }
            }
        }
    }
}

async fn run_command(
    pool: &mut RelayPool,
    command: Command,
    stop: &mut watch::Receiver<bool>,
) -> bool {
    match command {
        Command::Publish(event, response) => {
            tokio::select! {
                biased;
                _ = wait_for_stop(stop) => true,
                result = pool.publish(event) => {
                    let _ = response.send(result);
                    false
                }
            }
        }
        Command::Subscribe(id, filters, response) => {
            tokio::select! {
                biased;
                _ = wait_for_stop(stop) => true,
                result = pool.subscribe(id, filters) => {
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

fn stopped_pool_error() -> RelayPoolError {
    RelayPoolError::InvalidConfig("relay service stopped")
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
