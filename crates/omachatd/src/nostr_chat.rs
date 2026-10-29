use crate::{config::canonical_publication_url, ipc_server::EventHub};
use omachat_crypto::{NostrIdentityError, NostrSecret, npub_from_public_key, public_key_from_npub};
use omachat_nostr::{
    auth::RelayAuthSigner,
    dm_relay_list::create_dm_relay_list,
    event::EventLimits,
    gift_wrap::{
        CHAT_MESSAGE_KIND, ChatRecipient, GiftWrapPersistence, create_chat_rumor, create_gift_wrap,
        open_gift_wrap,
    },
    nip05::{self, Nip05Error},
    pool::{RelayPool, RelayPoolConfig, RelayPoolError},
    relay::{RelayAuthenticationPolicy, RelayConfig, RelayHealth, RelayNotification, RelayRoute},
};
use omachat_proto::ipc::{Event, Topic, VERSION};
use omachat_store::{NostrStoreError, NostrVault, SealedStore, StoreError};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::{
    error::Error,
    fmt,
    sync::{
        Arc, Mutex,
        atomic::{AtomicU64, Ordering},
    },
    time::{Duration, SystemTime, UNIX_EPOCH},
};
use tokio::{
    sync::{mpsc, oneshot},
    time::{Instant, sleep},
};
use zeroize::Zeroizing;

const CONTACTS_RECORD: &str = "nostr-contacts-v1";
const MESSAGES_RECORD: &str = "nostr-messages-v1";
const RELAYS_RECORD: &str = "nostr-relays-v1";
const MAX_CONTACTS: usize = 128;
const MAX_MESSAGES: usize = 128;
const MAX_TEXT_BYTES: usize = 4096;
const MAX_RELAYS: usize = 4;
const LOOKBACK_SECONDS: u64 = 30 * 24 * 60 * 60;
const CONNECT_WAIT: Duration = Duration::from_secs(8);

#[derive(Clone)]
pub struct NostrChat {
    requests: mpsc::Sender<ChatRequest>,
    relays: Arc<Mutex<Vec<String>>>,
}

enum ChatRequest {
    Prepare(oneshot::Sender<Result<Value, ChatError>>),
    AddContact(String, oneshot::Sender<Result<Value, ChatError>>),
    RemoveContact(String, oneshot::Sender<Result<Value, ChatError>>),
    ListContacts(oneshot::Sender<Result<Value, ChatError>>),
    ShowRelays(oneshot::Sender<Result<Value, ChatError>>),
    SetRelays(Vec<String>, oneshot::Sender<Result<Value, ChatError>>),
    Send(String, String, oneshot::Sender<Result<Value, ChatError>>),
    Messages(oneshot::Sender<Result<Value, ChatError>>),
    Reload(oneshot::Sender<Result<Value, ChatError>>),
    Snapshot(oneshot::Sender<Result<Value, ChatError>>),
    Loopback(Option<String>, oneshot::Sender<Result<Value, ChatError>>),
    Shutdown(oneshot::Sender<()>),
}

#[derive(Clone, Debug, Deserialize, Serialize)]
struct Contact {
    pubkey: String,
    npub: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    nip05: Option<String>,
    display: String,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
struct StoredMessage {
    id: String,
    conversation: String,
    peer: String,
    sender: String,
    text: String,
    outgoing: bool,
    delivery: String,
    created_at: u64,
}

struct Actor {
    store: Arc<SealedStore>,
    events: EventHub,
    sequence: Arc<AtomicU64>,
    relays: Arc<Mutex<Vec<String>>>,
    contacts: Vec<Contact>,
    messages: Vec<StoredMessage>,
    pool: Option<RelayPool>,
    pool_relays: Vec<String>,
    pool_pubkey: Option<String>,
    subscribed_for: Option<String>,
    loopback_nip05: Option<String>,
    limits: EventLimits,
}

impl NostrChat {
    pub fn spawn(
        store: Arc<SealedStore>,
        events: EventHub,
        sequence: Arc<AtomicU64>,
        configured_relays: Vec<String>,
    ) -> Self {
        let relays = load_relays(&store).unwrap_or(configured_relays);
        let relays = Arc::new(Mutex::new(relays));
        let (requests, inbox) = mpsc::channel(32);
        let actor = Actor {
            store,
            events,
            sequence,
            relays: Arc::clone(&relays),
            contacts: Vec::new(),
            messages: Vec::new(),
            pool: None,
            pool_relays: Vec::new(),
            pool_pubkey: None,
            subscribed_for: None,
            loopback_nip05: None,
            limits: EventLimits::default(),
        };
        tokio::spawn(actor.run(inbox));
        Self { requests, relays }
    }

    pub fn relays(&self) -> Vec<String> {
        self.relays
            .lock()
            .expect("relay list mutex poisoned")
            .clone()
    }

    pub async fn prepare(&self) -> Result<Value, ChatError> {
        self.roundtrip(ChatRequest::Prepare).await
    }

    pub async fn add_contact(&self, peer: &str) -> Result<Value, ChatError> {
        self.roundtrip(|reply| ChatRequest::AddContact(peer.to_owned(), reply))
            .await
    }

    pub async fn remove_contact(&self, npub: &str) -> Result<Value, ChatError> {
        self.roundtrip(|reply| ChatRequest::RemoveContact(npub.to_owned(), reply))
            .await
    }

    pub async fn list_contacts(&self) -> Result<Value, ChatError> {
        self.roundtrip(ChatRequest::ListContacts).await
    }

    pub async fn show_relays(&self) -> Result<Value, ChatError> {
        self.roundtrip(ChatRequest::ShowRelays).await
    }

    pub async fn set_relays(&self, relays: Vec<String>) -> Result<Value, ChatError> {
        self.roundtrip(|reply| ChatRequest::SetRelays(relays, reply))
            .await
    }

    pub async fn send(&self, peer: &str, text: &str) -> Result<Value, ChatError> {
        self.roundtrip(|reply| ChatRequest::Send(peer.to_owned(), text.to_owned(), reply))
            .await
    }

    pub async fn messages(&self) -> Result<Value, ChatError> {
        self.roundtrip(ChatRequest::Messages).await
    }

    pub async fn reload(&self) -> Result<Value, ChatError> {
        self.roundtrip(ChatRequest::Reload).await
    }

    pub async fn snapshot(&self) -> Result<Value, ChatError> {
        self.roundtrip(ChatRequest::Snapshot).await
    }

    pub async fn set_loopback_nip05(&self, base: Option<String>) -> Result<(), ChatError> {
        self.roundtrip(|reply| ChatRequest::Loopback(base, reply))
            .await
            .map(|_| ())
    }

    pub async fn shutdown(&self) {
        let (reply, waiter) = oneshot::channel();
        if self
            .requests
            .send(ChatRequest::Shutdown(reply))
            .await
            .is_ok()
        {
            let _ = waiter.await;
        }
    }

    async fn roundtrip(
        &self,
        build: impl FnOnce(oneshot::Sender<Result<Value, ChatError>>) -> ChatRequest,
    ) -> Result<Value, ChatError> {
        let (reply, waiter) = oneshot::channel();
        self.requests
            .send(build(reply))
            .await
            .map_err(|_| ChatError::Stopped)?;
        waiter.await.map_err(|_| ChatError::Stopped)?
    }
}

impl Actor {
    async fn run(mut self, mut requests: mpsc::Receiver<ChatRequest>) {
        self.contacts = load_contacts(&self.store).unwrap_or_default();
        self.messages = load_messages(&self.store).unwrap_or_default();
        self.restart_pool().await;
        loop {
            let notification = async {
                match self.pool.as_mut() {
                    Some(pool) => pool.next_notification().await,
                    None => std::future::pending().await,
                }
            };
            tokio::select! {
                request = requests.recv() => {
                    let Some(request) = request else { break };
                    if self.handle(request).await {
                        break;
                    }
                }
                notification = notification => {
                    if let Some(notification) = notification {
                        self.on_notification(notification.notification).await;
                    }
                }
            }
        }
        if let Some(pool) = self.pool.take() {
            pool.shutdown().await;
        }
    }

    async fn handle(&mut self, request: ChatRequest) -> bool {
        match request {
            ChatRequest::Prepare(reply) => {
                let _ = reply.send(self.prepare().await);
            }
            ChatRequest::AddContact(peer, reply) => {
                let _ = reply.send(self.add_contact(&peer).await);
            }
            ChatRequest::RemoveContact(npub, reply) => {
                let _ = reply.send(self.remove_contact(&npub));
            }
            ChatRequest::ListContacts(reply) => {
                let _ = reply.send(Ok(json!({"contacts": self.contacts})));
            }
            ChatRequest::ShowRelays(reply) => {
                let _ = reply.send(Ok(self.relay_value()));
            }
            ChatRequest::SetRelays(relays, reply) => {
                let _ = reply.send(self.set_relays(relays).await);
            }
            ChatRequest::Send(peer, text, reply) => {
                let _ = reply.send(self.send(&peer, &text).await);
            }
            ChatRequest::Messages(reply) => {
                let _ = reply.send(Ok(json!({"messages": self.messages})));
            }
            ChatRequest::Reload(reply) => {
                self.subscribed_for = None;
                self.restart_pool().await;
                let _ = reply.send(self.identity_value(false));
            }
            ChatRequest::Snapshot(reply) => {
                let _ = reply.send(Ok(self.snapshot_value()));
            }
            ChatRequest::Loopback(base, reply) => {
                self.loopback_nip05 = base;
                let _ = reply.send(Ok(json!({"ok": true})));
            }
            ChatRequest::Shutdown(reply) => {
                let _ = reply.send(());
                return true;
            }
        }
        false
    }

    async fn prepare(&mut self) -> Result<Value, ChatError> {
        let (_, generated) = self.ensure_identity()?;
        self.subscribed_for = None;
        self.restart_pool().await;
        self.identity_value(generated)
    }

    fn ensure_identity(&self) -> Result<(NostrSecret, bool), ChatError> {
        if let Some(secret) = NostrVault::load(&self.store)? {
            return Ok((secret, false));
        }
        let secret = NostrSecret::generate().map_err(ChatError::Identity)?;
        match NostrVault::save_new(&self.store, &secret) {
            Ok(()) => Ok((secret, true)),
            Err(NostrStoreError::AlreadyPresent) => {
                let secret = NostrVault::load(&self.store)?.ok_or(ChatError::Stopped)?;
                Ok((secret, false))
            }
            Err(error) => Err(ChatError::Store(error)),
        }
    }

    async fn add_contact(&mut self, peer: &str) -> Result<Value, ChatError> {
        let _ = self.ensure_identity()?;
        let (pubkey, nip05) = self.resolve_peer(peer).await?;
        let mine = self.load_secret()?.ok_or(ChatError::Stopped)?.public_key();
        if pubkey == mine {
            return Err(ChatError::SelfContact);
        }
        let encoded = hex::encode(pubkey);
        if let Some(existing) = self
            .contacts
            .iter()
            .find(|contact| contact.pubkey == encoded)
        {
            return Ok(json!({"contact": existing, "created": false}));
        }
        if self.contacts.len() >= MAX_CONTACTS {
            return Err(ChatError::TooLarge);
        }
        let npub = npub_from_public_key(&pubkey).map_err(ChatError::Identity)?;
        let contact = Contact {
            display: nip05.clone().unwrap_or_else(|| npub.clone()),
            pubkey: encoded,
            npub,
            nip05,
        };
        self.contacts.push(contact.clone());
        save_contacts(&self.store, &self.contacts)?;
        self.publish(
            Topic::Conversations,
            json!({"conversation": format!("dm:{}", contact.pubkey), "name": contact.display}),
        );
        self.ensure_pool().await;
        Ok(json!({"contact": contact, "created": true}))
    }

    fn remove_contact(&mut self, npub: &str) -> Result<Value, ChatError> {
        let pubkey = hex::encode(public_key_from_npub(npub).map_err(ChatError::Identity)?);
        let before = self.contacts.len();
        self.contacts.retain(|contact| contact.pubkey != pubkey);
        if self.contacts.len() == before {
            return Err(ChatError::NotFound);
        }
        save_contacts(&self.store, &self.contacts)?;
        Ok(json!({"removed": true}))
    }

    async fn set_relays(&mut self, relays: Vec<String>) -> Result<Value, ChatError> {
        let canonical = if relays.is_empty() {
            Vec::new()
        } else {
            canonical_relays(&relays)?
        };
        save_record(&self.store, RELAYS_RECORD, &json!({"relays": canonical}))?;
        *self.relays.lock().expect("relay list mutex poisoned") = canonical.clone();
        self.subscribed_for = None;
        self.restart_pool().await;
        Ok(self.relay_value())
    }

    async fn send(&mut self, peer: &str, text: &str) -> Result<Value, ChatError> {
        if text.is_empty()
            || text.len() > MAX_TEXT_BYTES
            || text
                .chars()
                .any(|character| character.is_control() && character != '\n' && character != '\t')
        {
            return Err(ChatError::InvalidText);
        }
        let (secret, _) = self.ensure_identity()?;
        self.ensure_pool().await;
        let (recipient, nip05) = self.resolve_peer(peer).await?;
        if recipient == secret.public_key() {
            return Err(ChatError::SelfContact);
        }
        self.remember_contact(&recipient, nip05)?;
        let now = unix_time()?;
        let rumor = create_chat_rumor(
            secret.raw_secret(),
            now,
            &[ChatRecipient {
                public_key: recipient,
                relay_hint: None,
            }],
            text.to_owned(),
            None,
            None,
            &self.limits,
        )
        .map_err(|error| ChatError::Send(error.to_string()))?;
        let recipient_wrap = create_gift_wrap(
            &rumor,
            secret.raw_secret(),
            &recipient,
            now,
            GiftWrapPersistence::Persistent,
            &self.limits,
        )
        .map_err(|error| ChatError::Send(error.to_string()))?;
        let self_wrap = create_gift_wrap(
            &rumor,
            secret.raw_secret(),
            &secret.public_key(),
            now,
            GiftWrapPersistence::Persistent,
            &self.limits,
        )
        .map_err(|error| ChatError::Send(error.to_string()))?;
        self.publish_to_relays(recipient_wrap).await?;
        self.publish_self_copy_for_other_devices(self_wrap).await;
        let message = self.store_message(StoredMessage {
            id: rumor.id,
            conversation: format!("dm:{}", hex::encode(recipient)),
            peer: hex::encode(recipient),
            sender: "you".into(),
            text: text.to_owned(),
            outgoing: true,
            delivery: "stored".into(),
            created_at: rumor.created_at,
        })?;
        Ok(json!({"message": message}))
    }

    async fn publish_self_copy_for_other_devices(&self, event: omachat_nostr::event::SignedEvent) {
        let _ = self.publish_to_relays(event).await;
    }

    async fn publish_to_relays(
        &self,
        event: omachat_nostr::event::SignedEvent,
    ) -> Result<(), ChatError> {
        let pool = self.pool.as_ref().ok_or(ChatError::NoRelays)?;
        if !wait_connected(pool).await {
            return Err(ChatError::NotConnected);
        }
        pool.publish(event)
            .await
            .map_err(|error| ChatError::Send(error.to_string()))?;
        Ok(())
    }

    fn remember_contact(
        &mut self,
        pubkey: &[u8; 32],
        nip05: Option<String>,
    ) -> Result<(), ChatError> {
        let encoded = hex::encode(pubkey);
        if self
            .contacts
            .iter()
            .any(|contact| contact.pubkey == encoded)
        {
            return Ok(());
        }
        if self.contacts.len() >= MAX_CONTACTS {
            return Err(ChatError::TooLarge);
        }
        let npub = npub_from_public_key(pubkey).map_err(ChatError::Identity)?;
        self.contacts.push(Contact {
            display: nip05.clone().unwrap_or_else(|| npub.clone()),
            pubkey: encoded,
            npub,
            nip05,
        });
        save_contacts(&self.store, &self.contacts)?;
        Ok(())
    }

    async fn resolve_peer(&self, peer: &str) -> Result<([u8; 32], Option<String>), ChatError> {
        let peer = peer.trim();
        if peer.contains('@') {
            let resolved = nip05::resolve_handle(peer, self.loopback_nip05.as_deref()).await?;
            return Ok((
                resolved.public_key,
                Some(format!("{}@{}", resolved.name, resolved.domain)),
            ));
        }
        if let Ok(pubkey) = public_key_from_npub(peer) {
            return Ok((pubkey, None));
        }
        if peer.len() == 64 && peer.bytes().all(|byte| byte.is_ascii_hexdigit()) {
            let mut pubkey = [0_u8; 32];
            hex::decode_to_slice(peer, &mut pubkey).map_err(|_| ChatError::InvalidPeer)?;
            k256::schnorr::VerifyingKey::from_bytes(&pubkey).map_err(|_| ChatError::InvalidPeer)?;
            return Ok((pubkey, None));
        }
        if let Some(contact) = self
            .contacts
            .iter()
            .find(|contact| contact.display.eq_ignore_ascii_case(peer) || contact.npub == peer)
        {
            let mut pubkey = [0_u8; 32];
            hex::decode_to_slice(&contact.pubkey, &mut pubkey)
                .map_err(|_| ChatError::InvalidPeer)?;
            return Ok((pubkey, contact.nip05.clone()));
        }
        Err(ChatError::InvalidPeer)
    }

    async fn ensure_pool(&mut self) {
        let relays = self.relays();
        let pubkey = self
            .load_secret()
            .ok()
            .flatten()
            .map(|secret| hex::encode(secret.public_key()));
        if self.pool.is_some() && self.pool_relays == relays && self.pool_pubkey == pubkey {
            self.ensure_subscription().await;
            return;
        }
        self.restart_pool().await;
    }

    async fn restart_pool(&mut self) {
        if let Some(pool) = self.pool.take() {
            pool.shutdown().await;
        }
        self.subscribed_for = None;
        let relays = self.relays();
        self.pool_relays = relays.clone();
        self.pool_pubkey = self
            .load_secret()
            .ok()
            .flatten()
            .map(|secret| hex::encode(secret.public_key()));
        if relays.is_empty() {
            return;
        }
        let signer = self.signer();
        let configs = relays
            .into_iter()
            .map(|url| {
                let mut config = RelayConfig::new(url, RelayRoute::Direct);
                config.authentication_policy =
                    RelayAuthenticationPolicy::AuthenticateWhenChallenged;
                config.connect_timeout = CONNECT_WAIT;
                config.response_timeout = Duration::from_secs(10);
                config.auth = signer.clone();
                config
            })
            .collect();
        let config = RelayPoolConfig {
            acknowledgement_threshold: 1,
            ..RelayPoolConfig::default()
        };
        if let Ok(pool) = RelayPool::spawn(configs, config) {
            self.pool = Some(pool);
            self.ensure_subscription().await;
        }
    }

    async fn ensure_subscription(&mut self) {
        let Some(secret) = self.load_secret().ok().flatten() else {
            return;
        };
        let pubkey = hex::encode(secret.public_key());
        if self.subscribed_for.as_deref() == Some(pubkey.as_str()) {
            return;
        }
        let since = unix_time().unwrap_or(0).saturating_sub(LOOKBACK_SECONDS);
        let filter = json!({
            "kinds": [1059],
            "#p": [pubkey],
            "since": since,
            "limit": 200
        });
        if let Some(pool) = self.pool.as_mut() {
            let _ = pool.subscribe("omachat-dm".into(), vec![filter]).await;
        }
        self.subscribed_for = Some(pubkey.clone());
        self.publish_inbox_list(&secret).await;
    }

    async fn publish_inbox_list(&mut self, secret: &NostrSecret) {
        let advertised = self
            .relays()
            .into_iter()
            .filter(|url| url.starts_with("wss://"))
            .take(3)
            .collect::<Vec<_>>();
        if advertised.is_empty() {
            return;
        }
        let Ok(now) = unix_time() else {
            return;
        };
        let Ok(event) = create_dm_relay_list(secret.raw_secret(), now, &advertised, &self.limits)
        else {
            return;
        };
        if let Some(pool) = self.pool.as_ref()
            && wait_connected(pool).await
        {
            let _ = pool.publish(event).await;
        }
    }

    async fn on_notification(&mut self, notification: RelayNotification) {
        let RelayNotification::Event { event, .. } = notification else {
            return;
        };
        if event.kind != 1059 {
            return;
        }
        let Some(secret) = self.load_secret().ok().flatten() else {
            return;
        };
        let Ok(now) = unix_time() else {
            return;
        };
        let Ok(opened) = open_gift_wrap(&event, secret.raw_secret(), now, &self.limits) else {
            return;
        };
        if opened.rumor.kind != CHAT_MESSAGE_KIND {
            return;
        }
        let text = opened.rumor.content;
        if text.len() > MAX_TEXT_BYTES {
            return;
        }
        let mine = hex::encode(secret.public_key());
        let outgoing = opened.rumor.pubkey == mine;
        let peer = if outgoing {
            opened
                .rumor
                .tags
                .iter()
                .find(|tag| tag.first().map(String::as_str) == Some("p"))
                .and_then(|tag| tag.get(1))
                .cloned()
        } else {
            Some(opened.rumor.pubkey.clone())
        };
        let Some(peer) = peer else {
            return;
        };
        if peer == mine
            || self
                .messages
                .iter()
                .any(|message| message.id == opened.rumor.id)
        {
            return;
        }
        let sender = if outgoing {
            "you".into()
        } else {
            display_for(&self.contacts, &peer)
        };
        let _ = self.store_message(StoredMessage {
            id: opened.rumor.id,
            conversation: format!("dm:{peer}"),
            peer,
            sender,
            text,
            outgoing,
            delivery: if outgoing { "stored" } else { "received" }.into(),
            created_at: opened.rumor.created_at,
        });
    }

    fn store_message(&mut self, message: StoredMessage) -> Result<StoredMessage, ChatError> {
        if self.messages.len() == MAX_MESSAGES {
            self.messages.remove(0);
        }
        self.messages.push(message.clone());
        save_messages(&self.store, &self.messages)?;
        self.publish(Topic::Messages, json!(message));
        Ok(message)
    }

    fn signer(&self) -> Option<RelayAuthSigner> {
        let secret = self.load_secret().ok().flatten()?;
        let bytes = Zeroizing::new(*secret.raw_secret());
        RelayAuthSigner::from_secret_key(*bytes).ok()
    }

    fn load_secret(&self) -> Result<Option<NostrSecret>, ChatError> {
        Ok(NostrVault::load(&self.store)?)
    }

    fn relays(&self) -> Vec<String> {
        self.relays
            .lock()
            .expect("relay list mutex poisoned")
            .clone()
    }

    fn identity_value(&self, generated: bool) -> Result<Value, ChatError> {
        let secret = self.load_secret()?.ok_or(ChatError::Stopped)?;
        Ok(json!({
            "npub": secret.npub(),
            "pubkey": hex::encode(secret.public_key()),
            "generated": generated,
        }))
    }

    fn relay_value(&self) -> Value {
        json!({"relays": self.relays()})
    }

    fn snapshot_value(&self) -> Value {
        let identity = self
            .load_secret()
            .ok()
            .flatten()
            .map(|secret| {
                json!({
                    "present": true,
                    "npub": secret.npub(),
                    "pubkey": hex::encode(secret.public_key()),
                })
            })
            .unwrap_or_else(|| json!({"present": false}));
        json!({
            "messages": self.messages,
            "contacts": self.contacts,
            "relays": self.relays(),
            "identity": identity,
        })
    }

    fn publish(&self, topic: Topic, payload: Value) {
        self.events.publish(Event {
            version: VERSION,
            sequence: self.sequence.fetch_add(1, Ordering::Relaxed),
            topic,
            payload,
        });
    }
}

fn display_for(contacts: &[Contact], pubkey: &str) -> String {
    contacts
        .iter()
        .find(|contact| contact.pubkey == pubkey)
        .map(|contact| contact.display.clone())
        .unwrap_or_else(|| {
            let mut raw = [0_u8; 32];
            if hex::decode_to_slice(pubkey, &mut raw).is_ok()
                && let Ok(npub) = npub_from_public_key(&raw)
            {
                npub
            } else {
                "peer".into()
            }
        })
}

fn canonical_relays(relays: &[String]) -> Result<Vec<String>, ChatError> {
    if relays.is_empty() || relays.len() > MAX_RELAYS {
        return Err(ChatError::InvalidRelay);
    }
    let mut canonical = Vec::with_capacity(relays.len());
    for relay in relays {
        let url = canonical_publication_url(relay).map_err(|_| ChatError::InvalidRelay)?;
        if canonical.iter().any(|existing| existing == &url) {
            return Err(ChatError::InvalidRelay);
        }
        canonical.push(url);
    }
    Ok(canonical)
}

async fn wait_connected(pool: &RelayPool) -> bool {
    let deadline = Instant::now() + CONNECT_WAIT;
    while Instant::now() < deadline {
        if pool.health().contains(&RelayHealth::Connected) {
            return true;
        }
        sleep(Duration::from_millis(25)).await;
    }
    false
}

fn unix_time() -> Result<u64, ChatError> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .map_err(|_| ChatError::Clock)
}

fn load_relays(store: &SealedStore) -> Option<Vec<String>> {
    let bytes = store.read(RELAYS_RECORD).ok()?;
    let value: Value = serde_json::from_slice(&bytes).ok()?;
    serde_json::from_value(value.get("relays")?.clone()).ok()
}

fn load_contacts(store: &SealedStore) -> Option<Vec<Contact>> {
    load_vec(store, CONTACTS_RECORD)
}

fn load_messages(store: &SealedStore) -> Option<Vec<StoredMessage>> {
    load_vec(store, MESSAGES_RECORD)
}

fn load_vec<T: for<'de> Deserialize<'de>>(store: &SealedStore, name: &str) -> Option<Vec<T>> {
    let bytes = store.read(name).ok()?;
    serde_json::from_slice(&bytes).ok()
}

fn save_contacts(store: &SealedStore, contacts: &[Contact]) -> Result<(), ChatError> {
    save_record(store, CONTACTS_RECORD, contacts)
}

fn save_messages(store: &SealedStore, messages: &[StoredMessage]) -> Result<(), ChatError> {
    save_record(store, MESSAGES_RECORD, messages)
}

fn save_record(
    store: &SealedStore,
    name: &str,
    value: &(impl Serialize + ?Sized),
) -> Result<(), ChatError> {
    let bytes = serde_json::to_vec(value).map_err(|_| ChatError::Corrupt)?;
    store.write(name, &bytes).map_err(ChatError::Sealed)
}

#[derive(Debug)]
pub enum ChatError {
    Store(NostrStoreError),
    Sealed(StoreError),
    Identity(NostrIdentityError),
    Nip05(Nip05Error),
    InvalidPeer,
    InvalidRelay,
    InvalidText,
    SelfContact,
    NoRelays,
    NotConnected,
    NotFound,
    TooLarge,
    Send(String),
    Corrupt,
    Clock,
    Stopped,
}

impl fmt::Display for ChatError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Store(error) => write!(formatter, "{error}"),
            Self::Sealed(error) => write!(formatter, "{error}"),
            Self::Identity(error) => write!(formatter, "{error}"),
            Self::Nip05(error) => write!(formatter, "{error}"),
            Self::InvalidPeer => formatter
                .write_str("contact must be an npub, a 64-character public key, or name@domain"),
            Self::InvalidRelay => formatter.write_str(
                "relays must be one to four distinct wss:// URLs, or numeric-loopback ws:// URLs",
            ),
            Self::InvalidText => {
                formatter.write_str("message text must be 1 to 4096 visible characters")
            }
            Self::SelfContact => formatter.write_str("that public key is this identity"),
            Self::NoRelays => {
                formatter.write_str("configure at least one Nostr relay before sending")
            }
            Self::NotConnected => formatter.write_str("no configured relay is connected"),
            Self::NotFound => formatter.write_str("no matching contact is stored"),
            Self::TooLarge => formatter.write_str("the local contact or message limit is full"),
            Self::Send(error) => write!(formatter, "Nostr send failed: {error}"),
            Self::Corrupt => formatter.write_str("stored Nostr chat state is corrupt"),
            Self::Clock => formatter.write_str("system clock is invalid"),
            Self::Stopped => formatter.write_str("Nostr chat service is stopped"),
        }
    }
}

impl Error for ChatError {}

impl From<NostrStoreError> for ChatError {
    fn from(error: NostrStoreError) -> Self {
        Self::Store(error)
    }
}

impl From<StoreError> for ChatError {
    fn from(error: StoreError) -> Self {
        Self::Sealed(error)
    }
}

impl From<Nip05Error> for ChatError {
    fn from(error: Nip05Error) -> Self {
        Self::Nip05(error)
    }
}

impl From<RelayPoolError> for ChatError {
    fn from(error: RelayPoolError) -> Self {
        Self::Send(error.to_string())
    }
}
