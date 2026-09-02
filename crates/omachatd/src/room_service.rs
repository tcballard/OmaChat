//! NIP-29 room runtime: one actor per configured room relay.
//!
//! Each actor owns the only path through which a relay's events reach the
//! room reducers. It binds the relay URL to the signing identity its NIP-11
//! document declares, opens that identity's sealed room state behind an
//! external generation anchor, keeps one logical room subscription in sync
//! with the joined set, and feeds every event the relay replays into the
//! reducers as "accepted by this authoritative relay path".
//!
//! That last step is the security boundary of the whole feature: the
//! `from_authoritative_relay` constructors are called here and nowhere else,
//! always with the key bound to the transport the event arrived on. Nothing
//! here signs: the core builds and signs join, leave, and message events and
//! hands the actor finished events, so secrets never enter this module.

use crate::nostr_service::{NostrHandle, NostrService, NostrServiceError};
use omachat_nostr::{
    event::{EventLimits, SignedEvent},
    nip11::{
        HttpRelayInformationFetcher, RelayInformation, RelayInformationLimits,
        RelayInformationSource,
    },
    nip29::{
        GROUP_ADMINS_KIND, GROUP_MEMBERS_KIND, GROUP_MESSAGE_KIND, GROUP_METADATA_KIND,
        GroupMembershipAction, GroupMetadata, GroupRoster, GroupUserAction, GroupUserEvent,
        JOIN_REQUEST_KIND, LEAVE_REQUEST_KIND, MembershipAction, PUT_USER_KIND, REMOVE_USER_KIND,
    },
    nip29_delete::{AcceptedGroupDeletion, DELETE_EVENT_KIND, GroupDeleteRequest},
    nip29_lifecycle::{
        AcceptedLifecycleAction, CREATE_GROUP_KIND, CREATE_INVITE_KIND, DELETE_GROUP_KIND,
        GroupLifecycleRequest, LifecycleApplyResult,
    },
    nip29_metadata::{
        AcceptedMetadataEdit, EDIT_METADATA_KIND, GroupMetadataEdit, MetadataApplyResult,
    },
    nip29_pins::{GROUP_PIN_LIST_KIND, GroupPinList},
    nip29_relay::{
        RelayIdentityObservation, RoomIdentityError, RoomSubscriptionSink, RoomSubscriptions,
        normalize_relay_url,
    },
    nip29_roles::{GROUP_ROLES_KIND, GroupRoles},
    nip29_room_state::RelayRoomState,
    nip29_state::MembershipApplyResult,
    pool::PoolNotification,
    relay::{RelayError, RelayNotification, RelayRoute},
};
use omachat_proto::ipc::Topic;
use omachat_store::{
    FileGenerationAnchor, RoomStateAnchorError, RoomStateVault, RoomStateVaultError, SealedStore,
    StoreError,
};
use serde_json::{Value, json};
use std::{
    collections::{BTreeMap, BTreeSet},
    error::Error,
    fmt,
    future::Future,
    path::PathBuf,
    sync::{Arc, Mutex},
    time::Duration,
};
use tokio::{
    sync::{mpsc, oneshot, watch},
    task::JoinHandle,
};

pub const ROOM_CONVERSATION_PREFIX: &str = "room:";
const JOINED_ROOMS_RECORD_PREFIX: &str = "nip29-joined-rooms-v1-";
const JOINED_ROOMS_RECORD_VERSION: u16 = 1;
const IDENTITY_RETRY: Duration = Duration::from_secs(30);
const IDENTITY_TIMEOUT: Duration = Duration::from_secs(15);
const COMMAND_CAPACITY: usize = 32;
const INBOUND_CAPACITY: usize = 256;

/// Publishes IPC events on the core's sequence.
pub type EventPublisher = Arc<dyn Fn(Topic, Value) + Send + Sync>;

/// Conversation ID for a room: `room:<relay signing key>:<group id>`.
#[must_use]
pub fn room_conversation_id(relay_pubkey: &str, group_id: &str) -> String {
    format!("{ROOM_CONVERSATION_PREFIX}{relay_pubkey}:{group_id}")
}

/// Split a room conversation ID into (relay signing key, group id).
#[must_use]
pub fn parse_room_conversation(conversation: &str) -> Option<(&str, &str)> {
    let rest = conversation.strip_prefix(ROOM_CONVERSATION_PREFIX)?;
    let (relay_pubkey, group_id) = rest.split_once(':')?;
    if relay_pubkey.len() != 64
        || !relay_pubkey
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        || group_id.is_empty()
    {
        return None;
    }
    Some((relay_pubkey, group_id))
}

#[derive(Clone, Debug)]
pub struct RoomServiceOptions {
    /// Canonical room relay URLs.
    pub relays: Vec<String>,
    pub route: RelayRoute,
    /// Anchor directory; must lie outside `state_directory`.
    pub anchor_directory: PathBuf,
    pub state_directory: PathBuf,
    /// Binds sealed room state to this daemon identity (device Nostr key).
    pub store_context: String,
    /// How far back the room subscription asks for messages.
    pub history_window_seconds: u64,
}

enum RoomCommand {
    Join {
        group_id: String,
        request: SignedEvent,
        reply: oneshot::Sender<Result<Value, RoomError>>,
    },
    Leave {
        group_id: String,
        request: SignedEvent,
        reply: oneshot::Sender<Result<Value, RoomError>>,
    },
    Publish {
        group_id: String,
        event: SignedEvent,
        reply: oneshot::Sender<Result<Value, RoomError>>,
    },
    Describe {
        reply: oneshot::Sender<Value>,
    },
}

/// One configured relay as seen by the core.
#[derive(Clone)]
pub struct RelayHandle {
    url: String,
    commands: mpsc::Sender<RoomCommand>,
    identity: Arc<Mutex<Option<String>>>,
}

impl RelayHandle {
    #[must_use]
    pub fn url(&self) -> &str {
        &self.url
    }

    /// The verified relay signing key, once NIP-11 discovery has bound it.
    #[must_use]
    pub fn relay_pubkey(&self) -> Option<String> {
        self.identity
            .lock()
            .expect("identity mutex poisoned")
            .clone()
    }

    pub async fn join(&self, group_id: String, request: SignedEvent) -> Result<Value, RoomError> {
        let (reply, receiver) = oneshot::channel();
        self.commands
            .send(RoomCommand::Join {
                group_id,
                request,
                reply,
            })
            .await
            .map_err(|_| RoomError::Stopped)?;
        receiver.await.map_err(|_| RoomError::Stopped)?
    }

    pub async fn leave(&self, group_id: String, request: SignedEvent) -> Result<Value, RoomError> {
        let (reply, receiver) = oneshot::channel();
        self.commands
            .send(RoomCommand::Leave {
                group_id,
                request,
                reply,
            })
            .await
            .map_err(|_| RoomError::Stopped)?;
        receiver.await.map_err(|_| RoomError::Stopped)?
    }

    pub async fn publish(&self, group_id: String, event: SignedEvent) -> Result<Value, RoomError> {
        let (reply, receiver) = oneshot::channel();
        self.commands
            .send(RoomCommand::Publish {
                group_id,
                event,
                reply,
            })
            .await
            .map_err(|_| RoomError::Stopped)?;
        receiver.await.map_err(|_| RoomError::Stopped)?
    }

    pub async fn describe(&self) -> Value {
        let (reply, receiver) = oneshot::channel();
        if self
            .commands
            .send(RoomCommand::Describe { reply })
            .await
            .is_err()
        {
            return json!({"relay": self.url, "status": "stopped"});
        }
        receiver
            .await
            .unwrap_or_else(|_| json!({"relay": self.url, "status": "stopped"}))
    }
}

/// Cloneable view over every room relay actor.
#[derive(Clone, Default)]
pub struct RoomsHandle {
    relays: Arc<BTreeMap<String, RelayHandle>>,
}

impl RoomsHandle {
    #[must_use]
    pub fn relay_urls(&self) -> Vec<String> {
        self.relays.keys().cloned().collect()
    }

    #[must_use]
    pub fn relay(&self, url: &str) -> Option<&RelayHandle> {
        let url = normalize_relay_url(url).ok()?;
        self.relays.get(&url)
    }

    /// The relay currently bound to a signing key, if any.
    #[must_use]
    pub fn relay_for_identity(&self, relay_pubkey: &str) -> Option<&RelayHandle> {
        self.relays
            .values()
            .find(|relay| relay.relay_pubkey().as_deref() == Some(relay_pubkey))
    }

    pub async fn describe_all(&self) -> Vec<Value> {
        let mut described = Vec::with_capacity(self.relays.len());
        for relay in self.relays.values() {
            described.push(relay.describe().await);
        }
        described
    }
}

pub struct RoomService {
    handle: RoomsHandle,
    stop: watch::Sender<bool>,
    tasks: Vec<JoinHandle<()>>,
}

impl RoomService {
    pub fn spawn(
        options: RoomServiceOptions,
        store: Arc<SealedStore>,
        publisher: EventPublisher,
    ) -> Result<Self, RoomServiceError> {
        let anchor = Arc::new(
            FileGenerationAnchor::open(&options.anchor_directory, &options.state_directory)
                .map_err(RoomServiceError::Anchor)?,
        );
        let (stop, stop_receiver) = watch::channel(false);
        let mut relays = BTreeMap::new();
        let mut tasks = Vec::new();
        for url in &options.relays {
            let url = normalize_relay_url(url).map_err(RoomServiceError::Identity)?;
            if relays.contains_key(&url) {
                continue;
            }
            let (sender, receiver) = mpsc::channel(COMMAND_CAPACITY);
            let identity = Arc::new(Mutex::new(None));
            let actor = RelayActor {
                url: url.clone(),
                route: options.route.clone(),
                store: Arc::clone(&store),
                anchor: Arc::clone(&anchor),
                store_context: options.store_context.clone(),
                history_window: options.history_window_seconds,
                publisher: Arc::clone(&publisher),
                identity_slot: Arc::clone(&identity),
                limits: EventLimits::default(),
                status: RelayStatus::DiscoveringIdentity,
            };
            tasks.push(tokio::spawn(actor.run(receiver, stop_receiver.clone())));
            relays.insert(
                url.clone(),
                RelayHandle {
                    url,
                    commands: sender,
                    identity,
                },
            );
        }
        Ok(Self {
            handle: RoomsHandle {
                relays: Arc::new(relays),
            },
            stop,
            tasks,
        })
    }

    #[must_use]
    pub fn handle(&self) -> RoomsHandle {
        self.handle.clone()
    }

    /// Stop every actor and wait for its relay connection to close.
    pub async fn shutdown(self) {
        let _ = self.stop.send(true);
        for task in self.tasks {
            let _ = task.await;
        }
    }
}

#[derive(Clone, Debug)]
enum RelayStatus {
    DiscoveringIdentity,
    IdentityUnavailable(String),
    NoIdentity,
    StateRefused(String),
    IdentityConflict(Value),
    Connecting,
    Connected,
    Disconnected,
    Failed(String),
}

impl RelayStatus {
    fn label(&self) -> &'static str {
        match self {
            Self::DiscoveringIdentity => "discovering-identity",
            Self::IdentityUnavailable(_) => "identity-unavailable",
            Self::NoIdentity => "no-relay-identity",
            Self::StateRefused(_) => "state-refused",
            Self::IdentityConflict(_) => "identity-conflict",
            Self::Connecting => "connecting",
            Self::Connected => "connected",
            Self::Disconnected => "disconnected",
            Self::Failed(_) => "failed",
        }
    }

    fn detail(&self) -> Value {
        match self {
            Self::IdentityUnavailable(detail)
            | Self::StateRefused(detail)
            | Self::Failed(detail) => Value::String(detail.clone()),
            Self::IdentityConflict(detail) => detail.clone(),
            _ => Value::Null,
        }
    }

    fn is_terminal(&self) -> bool {
        matches!(
            self,
            Self::StateRefused(_) | Self::IdentityConflict(_) | Self::Failed(_)
        )
    }
}

struct RelayActor {
    url: String,
    route: RelayRoute,
    store: Arc<SealedStore>,
    anchor: Arc<FileGenerationAnchor>,
    store_context: String,
    history_window: u64,
    publisher: EventPublisher,
    identity_slot: Arc<Mutex<Option<String>>>,
    limits: EventLimits,
    status: RelayStatus,
}

/// Which NIP-11 field supplied the relay signing key.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum IdentitySource {
    /// NIP-11 `self`: the relay's declared signing identity.
    SelfKey,
    /// NIP-11 `pubkey` on a relay that advertises NIP-29 but no `self`.
    /// Existing NIP-29 relays sign group state with this key; the `self`
    /// field postdates them. Recorded so the choice stays visible.
    PubkeyNip29Fallback,
}

impl IdentitySource {
    const fn label(self) -> &'static str {
        match self {
            Self::SelfKey => "self",
            Self::PubkeyNip29Fallback => "pubkey-nip29-fallback",
        }
    }
}

fn select_identity(information: &RelayInformation) -> Option<(String, IdentitySource)> {
    if let Some(key) = information.self_pubkey() {
        return Some((key.to_owned(), IdentitySource::SelfKey));
    }
    if information.supports_nip(29)
        && let Some(key) = information.pubkey()
    {
        return Some((key.to_owned(), IdentitySource::PubkeyNip29Fallback));
    }
    None
}

impl RelayActor {
    async fn run(
        mut self,
        mut commands: mpsc::Receiver<RoomCommand>,
        mut stop: watch::Receiver<bool>,
    ) {
        let Some((information, relay_pubkey, source)) =
            self.discover_identity(&mut commands, &mut stop).await
        else {
            return;
        };
        let store = Arc::clone(&self.store);
        let anchor = Arc::clone(&self.anchor);
        let mut vault =
            match RoomStateVault::open(&store, anchor.as_ref(), &self.store_context, &relay_pubkey)
            {
                Ok(vault) => vault,
                Err(error) => {
                    self.status = RelayStatus::StateRefused(error.to_string());
                    self.serve_terminal(&mut commands, &mut stop).await;
                    return;
                }
            };
        let Ok(now) = unix_time() else {
            self.status = RelayStatus::Failed("system clock is before the Unix epoch".into());
            self.serve_terminal(&mut commands, &mut stop).await;
            return;
        };
        let mut state = match vault.load_or_create(now, &self.limits) {
            Ok((state, _)) => state,
            Err(error) => {
                self.status = RelayStatus::StateRefused(error.to_string());
                self.serve_terminal(&mut commands, &mut stop).await;
                return;
            }
        };
        match state.identities_mut().observe_presented(
            &self.url,
            &relay_pubkey,
            information.software(),
            information.version(),
            now,
        ) {
            Ok(RelayIdentityObservation::Bound) => {
                if let Err(error) = vault.persist(&state) {
                    self.status = RelayStatus::StateRefused(error.to_string());
                    self.serve_terminal(&mut commands, &mut stop).await;
                    return;
                }
            }
            Ok(RelayIdentityObservation::Confirmed) => {}
            Err(RoomIdentityError::IdentityConflict(conflict)) => {
                self.status = RelayStatus::IdentityConflict(json!({
                    "url": conflict.url,
                    "trusted_pubkey": conflict.trusted_pubkey,
                    "presented_pubkey": conflict.presented_pubkey,
                    "first_verified_at": conflict.first_verified_at,
                    "last_verified_at": conflict.last_verified_at,
                    "observed_at": conflict.observed_at,
                    "trusted_software": conflict.trusted_software,
                    "presented_software": conflict.presented_software,
                    "presented_version": conflict.presented_version,
                    "assessment": "possible relay replacement or fork; the trusted binding was not changed",
                }));
                self.serve_terminal(&mut commands, &mut stop).await;
                return;
            }
            Err(error) => {
                self.status = RelayStatus::Failed(error.to_string());
                self.serve_terminal(&mut commands, &mut stop).await;
                return;
            }
        }
        *self.identity_slot.lock().expect("identity mutex poisoned") = Some(relay_pubkey.clone());

        let joined = match self.load_joined_rooms(&relay_pubkey) {
            Ok(joined) => joined,
            Err(error) => {
                self.status = RelayStatus::StateRefused(error.to_string());
                self.serve_terminal(&mut commands, &mut stop).await;
                return;
            }
        };
        let since = now.saturating_sub(self.history_window);
        let mut subscriptions = match RoomSubscriptions::new(relay_pubkey.clone(), Some(since)) {
            Ok(subscriptions) => subscriptions,
            Err(error) => {
                self.status = RelayStatus::Failed(error.to_string());
                self.serve_terminal(&mut commands, &mut stop).await;
                return;
            }
        };
        for group_id in &joined {
            let _ = subscriptions.join(group_id);
        }

        let (inbound_sender, mut inbound) = mpsc::channel(INBOUND_CAPACITY);
        let service = match NostrService::spawn_with_route(
            std::slice::from_ref(&self.url),
            self.route.clone(),
            inbound_sender,
        ) {
            Ok(service) => service,
            Err(error) => {
                self.status = RelayStatus::Failed(error.to_string());
                self.serve_terminal(&mut commands, &mut stop).await;
                return;
            }
        };
        let handle = service.handle();
        self.status = RelayStatus::Connecting;
        let mut sink = HandleSink(handle.clone());

        loop {
            tokio::select! {
                biased;
                _ = wait_for_stop(&mut stop) => break,
                command = commands.recv() => {
                    let Some(command) = command else { break };
                    self.handle_command(command, &handle, &mut sink, &mut subscriptions, &mut vault, &mut state, source).await;
                    if self.status.is_terminal() { break; }
                }
                notification = inbound.recv() => {
                    let Some(notification) = notification else {
                        self.status = RelayStatus::Failed("relay connection task ended".into());
                        break;
                    };
                    self.handle_notification(notification, &mut sink, &mut subscriptions, &mut vault, &mut state).await;
                    if self.status.is_terminal() { break; }
                }
            }
        }
        let _ = service.shutdown().await;
        if self.status.is_terminal() {
            self.serve_terminal(&mut commands, &mut stop).await;
        }
    }

    /// Fetch NIP-11 until a signing identity is available or the actor stops.
    async fn discover_identity(
        &mut self,
        commands: &mut mpsc::Receiver<RoomCommand>,
        stop: &mut watch::Receiver<bool>,
    ) -> Option<(RelayInformation, String, IdentitySource)> {
        let fetcher = HttpRelayInformationFetcher::new(
            self.route.clone(),
            IDENTITY_TIMEOUT,
            RelayInformationLimits::default(),
        );
        loop {
            if *stop.borrow() {
                return None;
            }
            match fetcher.fetch(&self.url).await {
                Ok(information) => match select_identity(&information) {
                    Some((key, source)) => return Some((information, key, source)),
                    None => self.status = RelayStatus::NoIdentity,
                },
                Err(error) => self.status = RelayStatus::IdentityUnavailable(error.to_string()),
            }
            let retry = tokio::time::sleep(IDENTITY_RETRY);
            tokio::pin!(retry);
            loop {
                tokio::select! {
                    biased;
                    _ = wait_for_stop(stop) => return None,
                    _ = &mut retry => break,
                    command = commands.recv() => {
                        let command = command?;
                        self.reject_command(command);
                    }
                }
            }
        }
    }

    /// Answer commands with the terminal status until stopped.
    async fn serve_terminal(
        &mut self,
        commands: &mut mpsc::Receiver<RoomCommand>,
        stop: &mut watch::Receiver<bool>,
    ) {
        loop {
            tokio::select! {
                biased;
                _ = wait_for_stop(stop) => return,
                command = commands.recv() => {
                    let Some(command) = command else { return };
                    self.reject_command(command);
                }
            }
        }
    }

    fn reject_command(&self, command: RoomCommand) {
        let unavailable = || RoomError::Unavailable {
            status: self.status.label().to_owned(),
            detail: self.status.detail(),
        };
        match command {
            RoomCommand::Join { reply, .. }
            | RoomCommand::Leave { reply, .. }
            | RoomCommand::Publish { reply, .. } => {
                let _ = reply.send(Err(unavailable()));
            }
            RoomCommand::Describe { reply } => {
                let _ = reply.send(json!({
                    "relay": self.url,
                    "status": self.status.label(),
                    "detail": self.status.detail(),
                    "relay_pubkey": self.identity_slot.lock().expect("identity mutex poisoned").clone(),
                    "rooms": [],
                }));
            }
        }
    }

    #[allow(clippy::too_many_arguments)]
    async fn handle_command(
        &mut self,
        command: RoomCommand,
        handle: &NostrHandle,
        sink: &mut HandleSink,
        subscriptions: &mut RoomSubscriptions,
        vault: &mut RoomStateVault<'_>,
        state: &mut RelayRoomState,
        source: IdentitySource,
    ) {
        match command {
            RoomCommand::Join {
                group_id,
                request,
                reply,
            } => {
                let result = self
                    .join(group_id, request, handle, sink, subscriptions, state)
                    .await;
                let _ = reply.send(result);
            }
            RoomCommand::Leave {
                group_id,
                request,
                reply,
            } => {
                let result = self
                    .leave(group_id, request, handle, sink, subscriptions, state)
                    .await;
                let _ = reply.send(result);
            }
            RoomCommand::Publish {
                group_id,
                event,
                reply,
            } => {
                let result = if !subscriptions.desired_rooms().contains(&group_id) {
                    Err(RoomError::NotJoined)
                } else if event.kind != GROUP_MESSAGE_KIND {
                    Err(RoomError::InvalidEvent)
                } else {
                    match handle.publish(event.clone()).await {
                        Ok(result) if result.accepted > 0 => Ok(json!({
                            "id": event.id,
                            "conversation": room_conversation_id(state.relay_pubkey(), &group_id),
                            "delivery": "stored",
                        })),
                        Ok(result) => Err(RoomError::Publish(describe_outcomes(&result.outcomes))),
                        Err(error) => Err(RoomError::Publish(error.to_string())),
                    }
                };
                let _ = reply.send(result);
            }
            RoomCommand::Describe { reply } => {
                let _ = reply.send(self.describe(subscriptions, state, vault.generation(), source));
            }
        }
    }

    async fn join(
        &mut self,
        group_id: String,
        request: SignedEvent,
        handle: &NostrHandle,
        sink: &mut HandleSink,
        subscriptions: &mut RoomSubscriptions,
        state: &RelayRoomState,
    ) -> Result<Value, RoomError> {
        if request.kind != JOIN_REQUEST_KIND {
            return Err(RoomError::InvalidEvent);
        }
        let inserted = subscriptions
            .join(&group_id)
            .map_err(|_| RoomError::InvalidGroup)?;
        if let Err(error) = subscriptions.sync(sink).await {
            // sync already reverted the desired set on rejection.
            return Err(RoomError::Subscription(error.to_string()));
        }
        if inserted
            && let Err(error) =
                self.save_joined_rooms(state.relay_pubkey(), subscriptions.desired_rooms())
        {
            subscriptions.leave(&group_id);
            let _ = subscriptions.sync(sink).await;
            return Err(RoomError::Persist(error.to_string()));
        }
        let delivery = match handle.publish(request.clone()).await {
            Ok(result) if result.accepted > 0 => "accepted".to_owned(),
            Ok(result) => format!("rejected: {}", describe_outcomes(&result.outcomes)),
            Err(error) => format!("failed: {error}"),
        };
        let conversation = room_conversation_id(state.relay_pubkey(), &group_id);
        self.publish_conversation(state, &group_id, "joined");
        Ok(json!({
            "joined": group_id,
            "conversation": conversation,
            "relay": self.url,
            "relay_pubkey": state.relay_pubkey(),
            "request_id": request.id,
            "request_delivery": delivery,
        }))
    }

    async fn leave(
        &mut self,
        group_id: String,
        request: SignedEvent,
        handle: &NostrHandle,
        sink: &mut HandleSink,
        subscriptions: &mut RoomSubscriptions,
        state: &RelayRoomState,
    ) -> Result<Value, RoomError> {
        if request.kind != LEAVE_REQUEST_KIND {
            return Err(RoomError::InvalidEvent);
        }
        if !subscriptions.desired_rooms().contains(&group_id) {
            return Err(RoomError::NotJoined);
        }
        let delivery = match handle.publish(request.clone()).await {
            Ok(result) if result.accepted > 0 => "accepted".to_owned(),
            Ok(result) => format!("rejected: {}", describe_outcomes(&result.outcomes)),
            Err(error) => format!("failed: {error}"),
        };
        subscriptions.leave(&group_id);
        if let Err(error) = subscriptions.sync(sink).await {
            return Err(RoomError::Subscription(error.to_string()));
        }
        self.save_joined_rooms(state.relay_pubkey(), subscriptions.desired_rooms())
            .map_err(|error| RoomError::Persist(error.to_string()))?;
        let conversation = room_conversation_id(state.relay_pubkey(), &group_id);
        self.publish_conversation(state, &group_id, "left");
        Ok(json!({
            "left": group_id,
            "conversation": conversation,
            "relay": self.url,
            "relay_pubkey": state.relay_pubkey(),
            "request_id": request.id,
            "request_delivery": delivery,
        }))
    }

    async fn handle_notification(
        &mut self,
        notification: PoolNotification,
        sink: &mut HandleSink,
        subscriptions: &mut RoomSubscriptions,
        vault: &mut RoomStateVault<'_>,
        state: &mut RelayRoomState,
    ) {
        match notification.notification {
            RelayNotification::Connected => {
                self.status = RelayStatus::Connected;
                // The pool replays stored subscriptions itself; this only
                // applies a desired set that was never accepted yet.
                if let Err(error) = subscriptions.sync(sink).await {
                    eprintln!(
                        "omachatd: room subscription on {} failed: {error}",
                        self.url
                    );
                }
            }
            RelayNotification::Disconnected => self.status = RelayStatus::Disconnected,
            RelayNotification::Event { event, .. } => {
                let Ok(now) = unix_time() else { return };
                match self.reduce_event(event, now, subscriptions, state) {
                    Reduction::Unchanged => {}
                    Reduction::Changed => {
                        if let Err(error) = vault.persist(state) {
                            self.status = RelayStatus::StateRefused(error.to_string());
                            eprintln!(
                                "omachatd: room state for {} could not be persisted; stopping the relay: {error}",
                                self.url
                            );
                        }
                    }
                }
            }
            RelayNotification::Closed {
                subscription_id,
                message,
            } => {
                eprintln!(
                    "omachatd: relay {} closed room subscription {subscription_id}: {message}",
                    self.url
                );
            }
            _ => {}
        }
    }

    /// Feed one relay-replayed event into the reducers.
    ///
    /// Every acceptance below is "the verified authoritative relay path for
    /// this room replayed it"; the relay key used is the one bound to this
    /// actor's transport, never a key taken from the event.
    fn reduce_event(
        &self,
        event: SignedEvent,
        now: u64,
        subscriptions: &RoomSubscriptions,
        state: &mut RelayRoomState,
    ) -> Reduction {
        let relay_pubkey = state.relay_pubkey().to_owned();
        let limits = &self.limits;
        match event.kind {
            GROUP_MESSAGE_KIND | JOIN_REQUEST_KIND | LEAVE_REQUEST_KIND => {
                let Ok(user_event) = GroupUserEvent::verify(event, now, limits) else {
                    return Reduction::Unchanged;
                };
                let group_id = user_event.group_id();
                if !subscriptions.desired_rooms().contains(group_id) {
                    return Reduction::Unchanged;
                }
                if matches!(user_event.action(), GroupUserAction::Message) {
                    let deleted = state
                        .group(group_id)
                        .is_some_and(|group| group.deletions().is_deleted(&user_event.event().id));
                    if !deleted {
                        (self.publisher)(
                            Topic::Messages,
                            json!({
                                "id": user_event.event().id,
                                "conversation": room_conversation_id(&relay_pubkey, group_id),
                                "sender": user_event.author(),
                                "text": user_event.event().content,
                                "created_at": user_event.event().created_at,
                                "delivery": "received",
                            }),
                        );
                    }
                }
                Reduction::Unchanged
            }
            PUT_USER_KIND | REMOVE_USER_KIND => {
                let Ok(action) = GroupMembershipAction::verify(event, now, limits) else {
                    return Reduction::Unchanged;
                };
                match state.apply_membership(&action) {
                    Ok(MembershipApplyResult::Applied) => {
                        let (public_key, member, roles) = match action.action() {
                            MembershipAction::Put { pubkey, roles } => {
                                (pubkey.clone(), true, roles.clone())
                            }
                            MembershipAction::Remove { pubkey } => {
                                (pubkey.clone(), false, Vec::new())
                            }
                        };
                        (self.publisher)(
                            Topic::Presence,
                            json!({
                                "conversation": room_conversation_id(&relay_pubkey, action.group_id()),
                                "public_key": public_key,
                                "member": member,
                                "roles": roles,
                                "source_event_id": action.event().id,
                            }),
                        );
                        Reduction::Changed
                    }
                    _ => Reduction::Unchanged,
                }
            }
            EDIT_METADATA_KIND => {
                let Ok(edit) = GroupMetadataEdit::verify(event, now, limits) else {
                    return Reduction::Unchanged;
                };
                let Ok(accepted) =
                    AcceptedMetadataEdit::from_authoritative_relay(edit, &relay_pubkey)
                else {
                    return Reduction::Unchanged;
                };
                let group_id = accepted.edit().group_id().to_owned();
                match state.metadata_mut().apply_accepted(&accepted) {
                    Ok(MetadataApplyResult::Recorded) => {
                        self.publish_conversation(state, &group_id, "metadata");
                        Reduction::Changed
                    }
                    _ => Reduction::Unchanged,
                }
            }
            DELETE_EVENT_KIND => {
                let Ok(request) = GroupDeleteRequest::verify(event, now, limits) else {
                    return Reduction::Unchanged;
                };
                let Ok(accepted) =
                    AcceptedGroupDeletion::from_authoritative_relay(request, &relay_pubkey)
                else {
                    return Reduction::Unchanged;
                };
                let group_id = accepted.request().group_id().to_owned();
                let requester = accepted.request().author().to_owned();
                let targets = accepted.request().targets().to_vec();
                match state.apply_deletion(&accepted) {
                    Ok(result) if result.newly_deleted > 0 => {
                        for target in targets {
                            (self.publisher)(
                                Topic::Messages,
                                json!({
                                    "id": target,
                                    "conversation": room_conversation_id(&relay_pubkey, &group_id),
                                    "deleted": true,
                                    "deleted_by": requester,
                                }),
                            );
                        }
                        Reduction::Changed
                    }
                    _ => Reduction::Unchanged,
                }
            }
            CREATE_GROUP_KIND | DELETE_GROUP_KIND | CREATE_INVITE_KIND => {
                let Ok(request) = GroupLifecycleRequest::verify(event, now, limits) else {
                    return Reduction::Unchanged;
                };
                let Ok(accepted) =
                    AcceptedLifecycleAction::from_authoritative_relay(request, &relay_pubkey)
                else {
                    return Reduction::Unchanged;
                };
                let group_id = accepted.request().group_id().to_owned();
                match state.lifecycle_mut().apply_accepted(&accepted) {
                    Ok(LifecycleApplyResult::Recorded) => {
                        self.publish_conversation(state, &group_id, "lifecycle");
                        Reduction::Changed
                    }
                    _ => Reduction::Unchanged,
                }
            }
            GROUP_METADATA_KIND => {
                let Ok(metadata) = GroupMetadata::verify(event, &relay_pubkey, now, limits) else {
                    return Reduction::Unchanged;
                };
                let group_id = metadata.group_id().to_owned();
                match state.metadata_mut().observe_snapshot(&metadata) {
                    Ok(MetadataApplyResult::Recorded) => {
                        self.publish_conversation(state, &group_id, "metadata");
                        Reduction::Changed
                    }
                    _ => Reduction::Unchanged,
                }
            }
            GROUP_ADMINS_KIND | GROUP_MEMBERS_KIND => {
                let Ok(roster) = GroupRoster::verify(event, &relay_pubkey, now, limits) else {
                    return Reduction::Unchanged;
                };
                match state.observe_roster(&roster) {
                    Ok(true) => Reduction::Changed,
                    _ => Reduction::Unchanged,
                }
            }
            GROUP_ROLES_KIND => {
                let Ok(roles) = GroupRoles::verify(event, &relay_pubkey, now, limits) else {
                    return Reduction::Unchanged;
                };
                match state.observe_roles(&roles) {
                    Ok(true) => Reduction::Changed,
                    _ => Reduction::Unchanged,
                }
            }
            GROUP_PIN_LIST_KIND => {
                let Ok(pins) = GroupPinList::verify(event, &relay_pubkey, now, limits) else {
                    return Reduction::Unchanged;
                };
                match state.observe_pins(&pins) {
                    Ok(true) => Reduction::Changed,
                    _ => Reduction::Unchanged,
                }
            }
            _ => Reduction::Unchanged,
        }
    }

    fn publish_conversation(&self, state: &RelayRoomState, group_id: &str, reason: &str) {
        (self.publisher)(
            Topic::Conversations,
            room_summary(&self.url, state, group_id, true, reason),
        );
    }

    fn describe(
        &self,
        subscriptions: &RoomSubscriptions,
        state: &RelayRoomState,
        generation: u64,
        source: IdentitySource,
    ) -> Value {
        let rooms = subscriptions
            .desired_rooms()
            .iter()
            .map(|group_id| {
                room_summary(
                    &self.url,
                    state,
                    group_id,
                    subscriptions.applied_rooms().contains(group_id),
                    "listed",
                )
            })
            .collect::<Vec<_>>();
        json!({
            "relay": self.url,
            "relay_pubkey": state.relay_pubkey(),
            "identity_source": source.label(),
            "status": self.status.label(),
            "detail": self.status.detail(),
            "state_generation": generation,
            "rooms": rooms,
        })
    }

    fn joined_record_name(relay_pubkey: &str) -> String {
        format!("{JOINED_ROOMS_RECORD_PREFIX}{relay_pubkey}")
    }

    fn load_joined_rooms(&self, relay_pubkey: &str) -> Result<BTreeSet<String>, RoomError> {
        let bytes = match self.store.read(&Self::joined_record_name(relay_pubkey)) {
            Ok(bytes) => bytes,
            Err(StoreError::RecordNotFound) => return Ok(BTreeSet::new()),
            Err(error) => return Err(RoomError::Persist(error.to_string())),
        };
        let value: Value = serde_json::from_slice(&bytes)
            .map_err(|_| RoomError::Persist("joined rooms record is malformed".into()))?;
        if value.get("version").and_then(Value::as_u64)
            != Some(u64::from(JOINED_ROOMS_RECORD_VERSION))
            || value.get("relay_pubkey").and_then(Value::as_str) != Some(relay_pubkey)
            || value.get("store_context").and_then(Value::as_str)
                != Some(self.store_context.as_str())
        {
            return Err(RoomError::Persist(
                "joined rooms record belongs to another relay, context, or version".into(),
            ));
        }
        value
            .get("rooms")
            .and_then(Value::as_array)
            .and_then(|rooms| {
                rooms
                    .iter()
                    .map(|room| room.as_str().map(str::to_owned))
                    .collect::<Option<BTreeSet<_>>>()
            })
            .filter(|rooms| rooms.iter().all(|room| !room.is_empty()))
            .ok_or_else(|| RoomError::Persist("joined rooms record is malformed".into()))
    }

    fn save_joined_rooms(
        &self,
        relay_pubkey: &str,
        rooms: &BTreeSet<String>,
    ) -> Result<(), StoreError> {
        let encoded = serde_json::to_vec(&json!({
            "version": JOINED_ROOMS_RECORD_VERSION,
            "relay_pubkey": relay_pubkey,
            "store_context": self.store_context,
            "rooms": rooms,
        }))
        .expect("joined rooms record serializes");
        self.store
            .write(&Self::joined_record_name(relay_pubkey), &encoded)
    }
}

fn room_summary(
    url: &str,
    state: &RelayRoomState,
    group_id: &str,
    subscribed: bool,
    reason: &str,
) -> Value {
    let metadata = state.metadata().group(group_id);
    let lifecycle = state
        .lifecycle()
        .status(group_id)
        .map(|status| format!("{status:?}").to_ascii_lowercase());
    let group = state.group(group_id);
    json!({
        "conversation": room_conversation_id(state.relay_pubkey(), group_id),
        "relay": url,
        "relay_pubkey": state.relay_pubkey(),
        "group_id": group_id,
        "name": metadata.map(|revision| revision.name().to_owned()),
        "about": metadata.map(|revision| revision.about().to_owned()),
        "private": metadata.map(|revision| revision.is_private()),
        "closed": metadata.map(|revision| revision.is_closed()),
        "lifecycle": lifecycle,
        "subscribed": subscribed,
        "member_count": group.map_or(0, |group| {
            let membership = group.membership();
            membership
                .snapshot()
                .records()
                .iter()
                .filter(|record| membership.is_member(record.pubkey()))
                .count()
        }),
        "admin_count": group.and_then(|group| group.admins()).map_or(0, |roster| roster.principals().len()),
        "pinned_count": group.and_then(|group| group.pins()).map_or(0, |pins| pins.pins().len()),
        "deleted_count": group.map_or(0, |group| group.deletions().len()),
        "reason": reason,
    })
}

enum Reduction {
    Unchanged,
    Changed,
}

fn describe_outcomes(outcomes: &[omachat_nostr::pool::RelayPublishOutcome]) -> String {
    outcomes
        .iter()
        .map(|outcome| format!("{outcome:?}"))
        .collect::<Vec<_>>()
        .join("; ")
}

/// Room subscription sink over the daemon's relay service actor.
struct HandleSink(NostrHandle);

impl RoomSubscriptionSink for HandleSink {
    fn subscribe(
        &mut self,
        subscription_id: String,
        filters: Vec<Value>,
    ) -> impl Future<Output = Vec<Result<(), RelayError>>> + Send {
        let handle = self.0.clone();
        async move {
            match handle.subscribe_results(subscription_id, filters).await {
                Ok(results) => results,
                Err(_) => vec![Err(RelayError::Stopped)],
            }
        }
    }

    fn close_subscription(
        &mut self,
        subscription_id: String,
    ) -> impl Future<Output = Vec<Result<(), RelayError>>> + Send {
        let handle = self.0.clone();
        async move {
            match handle.close_subscription_results(subscription_id).await {
                Ok(results) => results,
                Err(_) => vec![Err(RelayError::Stopped)],
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

fn unix_time() -> Result<u64, ()> {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .map_err(|_| ())
}

#[derive(Debug)]
pub enum RoomError {
    Unavailable { status: String, detail: Value },
    NotJoined,
    InvalidGroup,
    InvalidEvent,
    Subscription(String),
    Publish(String),
    Persist(String),
    Stopped,
}

impl fmt::Display for RoomError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Unavailable { status, detail } => {
                write!(formatter, "room relay is not ready ({status}): {detail}")
            }
            Self::NotJoined => formatter.write_str("room is not joined on this relay"),
            Self::InvalidGroup => formatter.write_str("room group ID is invalid"),
            Self::InvalidEvent => formatter.write_str("event kind does not match the room action"),
            Self::Subscription(detail) => write!(formatter, "room subscription failed: {detail}"),
            Self::Publish(detail) => {
                write!(formatter, "room relay did not accept the event: {detail}")
            }
            Self::Persist(detail) => {
                write!(formatter, "room state could not be persisted: {detail}")
            }
            Self::Stopped => formatter.write_str("room relay service stopped"),
        }
    }
}

impl Error for RoomError {}

#[derive(Debug)]
pub enum RoomServiceError {
    Anchor(RoomStateAnchorError),
    Identity(RoomIdentityError),
    Vault(RoomStateVaultError),
    Service(NostrServiceError),
}

impl fmt::Display for RoomServiceError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Anchor(error) => write!(formatter, "room state anchor: {error}"),
            Self::Identity(error) => write!(formatter, "room relay identity: {error}"),
            Self::Vault(error) => write!(formatter, "room state: {error}"),
            Self::Service(error) => write!(formatter, "room relay service: {error}"),
        }
    }
}

impl Error for RoomServiceError {}
