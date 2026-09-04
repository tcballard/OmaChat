use omachat_nostr::{
    event::SignedEvent,
    pool::{PoolNotification, PoolPublishResult, RelayPool, RelayPoolConfig, RelayPoolError},
    relay::{RelayConfig, RelayHealth, RelayNotification, RelayRoute},
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

struct Inbound {
    sender: mpsc::Sender<PoolNotification>,
    cell: Option<String>,
}

impl Inbound {
    fn accepts(&self, notification: &PoolNotification) -> bool {
        let Some(cell) = &self.cell else {
            return true;
        };
        match &notification.notification {
            RelayNotification::Event { event, .. } => {
                matches!(event.kind, 20000 | 20001)
                    && event
                        .tags
                        .iter()
                        .filter(|tag| tag.first().is_some_and(|key| key == "g"))
                        .count()
                        == 1
                    && event.tags.iter().any(|tag| {
                        tag.first().is_some_and(|key| key == "g") && tag.get(1) == Some(cell)
                    })
            }
            _ => true,
        }
    }
}

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
    CloseSubscription(
        String,
        oneshot::Sender<Vec<Result<(), omachat_nostr::relay::RelayError>>>,
    ),
}

#[derive(Clone)]
pub struct NostrHandle {
    commands: mpsc::Sender<Command>,
    accepting: Arc<AtomicBool>,
    stop: watch::Sender<bool>,
    stopped: watch::Receiver<bool>,
    health: watch::Receiver<Vec<RelayHealth>>,
}
impl NostrHandle {
    pub fn health(&self) -> Vec<RelayHealth> {
        self.health.borrow().clone()
    }
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
        let results = self.subscribe_results(id, filters).await?;
        if results.iter().any(Result::is_ok) {
            Ok(())
        } else {
            Err(NostrServiceError::Subscription)
        }
    }

    /// Replace a subscription and return every relay's verdict, in pool order.
    pub async fn subscribe_results(
        &self,
        id: String,
        filters: Vec<Value>,
    ) -> Result<Vec<Result<(), omachat_nostr::relay::RelayError>>, NostrServiceError> {
        if !self.accepting.load(Ordering::Acquire) {
            return Err(NostrServiceError::Stopped);
        }
        let (sender, receiver) = oneshot::channel();
        self.commands
            .send(Command::Subscribe(id, filters, sender))
            .await
            .map_err(|_| NostrServiceError::Stopped)?;
        receiver.await.map_err(|_| NostrServiceError::Stopped)
    }

    /// Close a subscription and return every relay's verdict, in pool order.
    pub async fn close_subscription_results(
        &self,
        id: String,
    ) -> Result<Vec<Result<(), omachat_nostr::relay::RelayError>>, NostrServiceError> {
        if !self.accepting.load(Ordering::Acquire) {
            return Err(NostrServiceError::Stopped);
        }
        let (sender, receiver) = oneshot::channel();
        self.commands
            .send(Command::CloseSubscription(id, sender))
            .await
            .map_err(|_| NostrServiceError::Stopped)?;
        receiver.await.map_err(|_| NostrServiceError::Stopped)
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
        Self::spawn_with_route(urls, RelayRoute::Direct, inbound)
    }

    /// Spawn a pool whose every relay is dialed over the given route.
    pub fn spawn_with_route(
        urls: &[String],
        route: RelayRoute,
        inbound: mpsc::Sender<PoolNotification>,
    ) -> Result<Self, RelayPoolError> {
        Self::spawn_inner(urls, route, inbound, None)
    }

    pub(crate) fn spawn_geo(
        urls: &[String],
        cell: String,
        inbound: mpsc::Sender<PoolNotification>,
    ) -> Result<Self, RelayPoolError> {
        Self::spawn_inner(urls, RelayRoute::Direct, inbound, Some(cell))
    }

    fn spawn_inner(
        urls: &[String],
        route: RelayRoute,
        inbound: mpsc::Sender<PoolNotification>,
        cell: Option<String>,
    ) -> Result<Self, RelayPoolError> {
        let configs = urls
            .iter()
            .cloned()
            .map(|url| RelayConfig::new(url, route.clone()))
            .collect();
        let pool = RelayPool::spawn(configs, RelayPoolConfig::default())?;
        let (sender, receiver) = mpsc::channel(COMMAND_CAPACITY);
        let accepting = Arc::new(AtomicBool::new(true));
        let (stop, stop_receiver) = watch::channel(false);
        let (stopped_sender, stopped) = watch::channel(false);
        let (health_sender, health) = watch::channel(pool.health());
        let handle = NostrHandle {
            commands: sender,
            accepting: Arc::clone(&accepting),
            stop,
            stopped,
            health,
        };
        let task = tokio::spawn(run(
            pool,
            receiver,
            Inbound {
                sender: inbound,
                cell,
            },
            stop_receiver,
            accepting,
            stopped_sender,
            health_sender,
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
    inbound: Inbound,
    mut stop: watch::Receiver<bool>,
    accepting: Arc<AtomicBool>,
    stopped: watch::Sender<bool>,
    health: watch::Sender<Vec<RelayHealth>>,
) -> Result<(), RelayPoolError> {
    run_until_stopped(&mut pool, &mut commands, &inbound, &mut stop, &health).await;

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
    inbound: &Inbound,
    stop: &mut watch::Receiver<bool>,
    health: &watch::Sender<Vec<RelayHealth>>,
) {
    loop {
        health.send_if_modified(|current| {
            let next = pool.health();
            if *current == next {
                false
            } else {
                *current = next;
                true
            }
        });
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
                    if !inbound.accepts(&notification) { continue; }
                    tokio::select! {
                        biased;
                        _ = wait_for_stop(stop) => return,
                        result = inbound.sender.send(notification) => {
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
        Command::CloseSubscription(id, response) => {
            tokio::select! {
                biased;
                _ = wait_for_stop(stop) => true,
                result = pool.close_subscription(id) => {
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

#[cfg(test)]
mod geo_filter_tests {
    use super::*;

    #[test]
    fn geographic_input_rejects_other_cells_private_mail_and_ambiguous_tags() {
        let (sender, _) = mpsc::channel(1);
        let input = Inbound {
            sender,
            cell: Some("gcpvj".into()),
        };
        let mut event = SignedEvent {
            id: String::new(),
            pubkey: String::new(),
            created_at: 0,
            kind: 20000,
            tags: vec![vec!["g".into(), "gcpvj".into()]],
            content: String::new(),
            sig: String::new(),
        };
        let accepts = |event| {
            input.accepts(&PoolNotification {
                relay_index: 0,
                notification: RelayNotification::Event {
                    subscription_id: "geo".into(),
                    event,
                },
            })
        };
        assert!(accepts(event.clone()));
        event.kind = 1059;
        assert!(!accepts(event.clone()));
        event.kind = 20001;
        event.tags[0][1] = "u4pruy".into();
        assert!(!accepts(event.clone()));
        event.tags.push(vec!["g".into(), "gcpvj".into()]);
        assert!(!accepts(event));
    }
}
