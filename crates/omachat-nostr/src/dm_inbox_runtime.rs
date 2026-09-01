use std::{collections::HashSet, error::Error, fmt, time::Duration};

use tokio::time::{Instant, timeout};
use url::Url;
use zeroize::Zeroizing;

use crate::{
    auth::RelayAuthSigner,
    dm_inbox::{DmInbox, DmInboxConfig, DmInboxError, DmInboxReceive},
    event::SignedEvent,
    gift_wrap::GIFT_WRAP_KIND,
    pool::{PoolPublishResult, RelayPool, RelayPoolConfig, RelayPoolError},
    relay::{RelayConfig, RelayError, RelayNotification},
};

const DEFAULT_AUTHENTICATION_TIMEOUT: Duration = Duration::from_secs(10);
const DEFAULT_SUBSCRIPTION_ID: &str = "omachat-nip17-inbox";
const MAX_SUBSCRIPTION_ID_BYTES: usize = 64;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DmInboxRuntimeConfig {
    pub inbox: DmInboxConfig,
    pub pool: RelayPoolConfig,
    pub authentication_timeout: Duration,
    pub subscription_id: String,
}

impl Default for DmInboxRuntimeConfig {
    fn default() -> Self {
        Self {
            inbox: DmInboxConfig::default(),
            pool: RelayPoolConfig::default(),
            authentication_timeout: DEFAULT_AUTHENTICATION_TIMEOUT,
            subscription_id: DEFAULT_SUBSCRIPTION_ID.to_owned(),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DmInboxRuntimeEvent {
    pub relay_index: usize,
    pub receive: DmInboxReceive,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum DmInboxRuntimeActivity {
    Inbox(DmInboxRuntimeEvent),
    AuthenticationRestored,
}

#[derive(Debug)]
pub enum DmInboxRuntimeError {
    InvalidConfig(&'static str),
    InvalidRelayUrl {
        relay_index: usize,
    },
    DuplicateRelay {
        relay_index: usize,
    },
    InvalidRecipientSecret,
    IdentityMismatch,
    Pool(RelayPoolError),
    AuthenticationTimeout {
        authenticated: usize,
        required: usize,
    },
    AuthenticationRejected {
        relay_index: usize,
        message: String,
    },
    UnexpectedAuthenticationIdentity {
        relay_index: usize,
        public_key: String,
    },
    SubscriptionRejected {
        relay_index: usize,
        error: RelayError,
    },
    SubscriptionClosed {
        relay_index: usize,
        message: String,
    },
    UnauthenticatedEvent {
        relay_index: usize,
    },
    UnauthenticatedPublish {
        authenticated: usize,
        required: usize,
    },
    InvalidOutboundGiftWrap,
    OutboundRecipientMismatch,
    Inbox(DmInboxError),
    Stopped,
}

impl fmt::Display for DmInboxRuntimeError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidConfig(message) => {
                write!(formatter, "invalid inbox runtime config: {message}")
            }
            Self::InvalidRelayUrl { relay_index } => {
                write!(
                    formatter,
                    "relay {relay_index} has an invalid WebSocket URL"
                )
            }
            Self::DuplicateRelay { relay_index } => {
                write!(
                    formatter,
                    "relay {relay_index} duplicates another relay identity"
                )
            }
            Self::InvalidRecipientSecret => formatter.write_str("invalid recipient secret key"),
            Self::IdentityMismatch => formatter.write_str(
                "NIP-42 authentication identity does not match the inbox recipient identity",
            ),
            Self::Pool(error) => write!(formatter, "relay pool failed: {error}"),
            Self::AuthenticationTimeout {
                authenticated,
                required,
            } => write!(
                formatter,
                "relay authentication timed out after {authenticated} of {required} relays",
            ),
            Self::AuthenticationRejected {
                relay_index,
                message,
            } => write!(
                formatter,
                "relay {relay_index} rejected inbox authentication: {message}",
            ),
            Self::UnexpectedAuthenticationIdentity {
                relay_index,
                public_key,
            } => write!(
                formatter,
                "relay {relay_index} authenticated unexpected identity {public_key}",
            ),
            Self::SubscriptionRejected { relay_index, error } => {
                write!(
                    formatter,
                    "relay {relay_index} rejected inbox subscription: {error}"
                )
            }
            Self::SubscriptionClosed {
                relay_index,
                message,
            } => write!(
                formatter,
                "relay {relay_index} closed the inbox subscription: {message}",
            ),
            Self::UnauthenticatedEvent { relay_index } => write!(
                formatter,
                "relay {relay_index} delivered an inbox event before authentication",
            ),
            Self::UnauthenticatedPublish {
                authenticated,
                required,
            } => write!(
                formatter,
                "cannot publish with only {authenticated} of {required} authenticated relays",
            ),
            Self::InvalidOutboundGiftWrap => {
                formatter.write_str("outbound event is not a valid persistent NIP-17 gift wrap")
            }
            Self::OutboundRecipientMismatch => formatter
                .write_str("outbound gift-wrap recipient does not match the requested recipient"),
            Self::Inbox(error) => write!(formatter, "inbox event rejected: {error}"),
            Self::Stopped => formatter.write_str("relay pool stopped"),
        }
    }
}

impl Error for DmInboxRuntimeError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Pool(error) => Some(error),
            Self::SubscriptionRejected { error, .. } => Some(error),
            Self::Inbox(error) => Some(error),
            _ => None,
        }
    }
}

impl From<RelayPoolError> for DmInboxRuntimeError {
    fn from(error: RelayPoolError) -> Self {
        Self::Pool(error)
    }
}

impl From<DmInboxError> for DmInboxRuntimeError {
    fn from(error: DmInboxError) -> Self {
        Self::Inbox(error)
    }
}

pub struct AuthenticatedDmInboxRuntime {
    pool: RelayPool,
    inbox: DmInbox,
    recipient_secret_key: Zeroizing<[u8; 32]>,
    recipient_public_key: String,
    authenticated_relays: HashSet<usize>,
    relay_count: usize,
    subscription_id: String,
}

impl AuthenticatedDmInboxRuntime {
    pub async fn connect(
        mut relay_configs: Vec<RelayConfig>,
        auth_signer: RelayAuthSigner,
        recipient_secret_key: [u8; 32],
        config: DmInboxRuntimeConfig,
        now: u64,
    ) -> Result<Self, DmInboxRuntimeError> {
        validate_config(&relay_configs, &config)?;

        let recipient_signer = RelayAuthSigner::from_secret_key(recipient_secret_key)
            .map_err(|_| DmInboxRuntimeError::InvalidRecipientSecret)?;
        if recipient_signer.public_key() != auth_signer.public_key() {
            return Err(DmInboxRuntimeError::IdentityMismatch);
        }

        let recipient_public_key = hex::encode(recipient_signer.public_key());
        let inbox = DmInbox::new(config.inbox)?;
        let filter = inbox.subscription_filter(&recipient_public_key, now)?;

        for relay_config in &mut relay_configs {
            relay_config.auth = Some(auth_signer.clone());
        }

        let relay_count = relay_configs.len();
        let mut pool = RelayPool::spawn(relay_configs, config.pool)?;
        let authenticated_relays = match wait_for_authentication(
            &mut pool,
            relay_count,
            &recipient_public_key,
            config.authentication_timeout,
        )
        .await
        {
            Ok(authenticated_relays) => authenticated_relays,
            Err(error) => {
                let _ = pool.shutdown().await;
                return Err(error);
            }
        };

        let subscription_results = pool
            .subscribe(config.subscription_id.clone(), vec![filter])
            .await;
        if subscription_results.len() != relay_count {
            let _ = pool.shutdown().await;
            return Err(DmInboxRuntimeError::Stopped);
        }
        if let Some((relay_index, error)) = subscription_results
            .into_iter()
            .enumerate()
            .find_map(|(relay_index, result)| result.err().map(|error| (relay_index, error)))
        {
            let _ = pool.shutdown().await;
            return Err(DmInboxRuntimeError::SubscriptionRejected { relay_index, error });
        }

        Ok(Self {
            pool,
            inbox,
            recipient_secret_key: Zeroizing::new(recipient_secret_key),
            recipient_public_key,
            authenticated_relays,
            relay_count,
            subscription_id: config.subscription_id,
        })
    }

    pub fn recipient_public_key(&self) -> &str {
        &self.recipient_public_key
    }

    pub fn relay_count(&self) -> usize {
        self.relay_count
    }

    pub fn block_author(
        &mut self,
        author_xonly_public_key: &str,
    ) -> Result<(), DmInboxRuntimeError> {
        self.inbox
            .block_author(author_xonly_public_key)
            .map_err(Into::into)
    }

    pub fn unblock_author(
        &mut self,
        author_xonly_public_key: &str,
    ) -> Result<(), DmInboxRuntimeError> {
        self.inbox
            .unblock_author(author_xonly_public_key)
            .map_err(Into::into)
    }

    pub async fn publish(
        &self,
        event: SignedEvent,
        recipient_xonly_public_key: &str,
        now: u64,
    ) -> Result<PoolPublishResult, DmInboxRuntimeError> {
        if self.authenticated_relays.len() != self.relay_count {
            return Err(DmInboxRuntimeError::UnauthenticatedPublish {
                authenticated: self.authenticated_relays.len(),
                required: self.relay_count,
            });
        }
        self.inbox
            .subscription_filter(recipient_xonly_public_key, now)?;
        if event.kind != GIFT_WRAP_KIND
            || event
                .verify(now, &self.inbox.config().event_limits)
                .is_err()
        {
            return Err(DmInboxRuntimeError::InvalidOutboundGiftWrap);
        }
        let mut recipient_tags = event
            .tags
            .iter()
            .filter(|tag| tag.first().is_some_and(|name| name == "p"));
        let recipient_matches = recipient_tags
            .next()
            .is_some_and(|tag| tag.len() == 2 && tag[1] == recipient_xonly_public_key);
        if !recipient_matches || recipient_tags.next().is_some() {
            return Err(DmInboxRuntimeError::OutboundRecipientMismatch);
        }
        self.pool.publish(event).await.map_err(Into::into)
    }

    pub async fn next(&mut self, now: u64) -> Result<DmInboxRuntimeEvent, DmInboxRuntimeError> {
        loop {
            match self.next_activity(now).await? {
                DmInboxRuntimeActivity::Inbox(event) => return Ok(event),
                DmInboxRuntimeActivity::AuthenticationRestored => {}
            }
        }
    }

    pub async fn next_activity(
        &mut self,
        now: u64,
    ) -> Result<DmInboxRuntimeActivity, DmInboxRuntimeError> {
        loop {
            let notification = self
                .pool
                .next_notification()
                .await
                .ok_or(DmInboxRuntimeError::Stopped)?;
            let relay_index = notification.relay_index;

            match notification.notification {
                RelayNotification::Connected
                | RelayNotification::Disconnected
                | RelayNotification::AuthChallenge(_) => {
                    self.authenticated_relays.remove(&relay_index);
                }
                RelayNotification::Authenticated { public_key } => {
                    if public_key != self.recipient_public_key {
                        return Err(DmInboxRuntimeError::UnexpectedAuthenticationIdentity {
                            relay_index,
                            public_key,
                        });
                    }
                    let was_fully_authenticated =
                        self.authenticated_relays.len() == self.relay_count;
                    self.authenticated_relays.insert(relay_index);
                    if !was_fully_authenticated
                        && self.authenticated_relays.len() == self.relay_count
                    {
                        return Ok(DmInboxRuntimeActivity::AuthenticationRestored);
                    }
                }
                RelayNotification::AuthenticationRejected { message, .. } => {
                    self.authenticated_relays.remove(&relay_index);
                    return Err(DmInboxRuntimeError::AuthenticationRejected {
                        relay_index,
                        message,
                    });
                }
                RelayNotification::Event {
                    subscription_id,
                    event,
                } => {
                    if subscription_id != self.subscription_id {
                        continue;
                    }
                    if !self.authenticated_relays.contains(&relay_index) {
                        return Err(DmInboxRuntimeError::UnauthenticatedEvent { relay_index });
                    }

                    let receive = self
                        .inbox
                        .receive(&event, &self.recipient_secret_key, now)?;
                    return Ok(DmInboxRuntimeActivity::Inbox(DmInboxRuntimeEvent {
                        relay_index,
                        receive,
                    }));
                }
                RelayNotification::Closed {
                    subscription_id,
                    message,
                } if subscription_id == self.subscription_id => {
                    return Err(DmInboxRuntimeError::SubscriptionClosed {
                        relay_index,
                        message,
                    });
                }
                RelayNotification::EndOfStoredEvents { .. }
                | RelayNotification::Closed { .. }
                | RelayNotification::Notice(_) => {}
            }
        }
    }

    pub async fn shutdown(self) -> Vec<Result<(), RelayError>> {
        self.pool.shutdown().await
    }
}

fn validate_config(
    relay_configs: &[RelayConfig],
    config: &DmInboxRuntimeConfig,
) -> Result<(), DmInboxRuntimeError> {
    if relay_configs.is_empty() {
        return Err(DmInboxRuntimeError::InvalidConfig(
            "at least one relay is required",
        ));
    }
    if config.authentication_timeout.is_zero() {
        return Err(DmInboxRuntimeError::InvalidConfig(
            "authentication timeout must be non-zero",
        ));
    }
    if config.subscription_id.is_empty() || config.subscription_id.len() > MAX_SUBSCRIPTION_ID_BYTES
    {
        return Err(DmInboxRuntimeError::InvalidConfig(
            "subscription id must contain between 1 and 64 bytes",
        ));
    }

    let mut relay_identities = HashSet::with_capacity(relay_configs.len());
    for (relay_index, relay_config) in relay_configs.iter().enumerate() {
        let parsed = Url::parse(&relay_config.url)
            .map_err(|_| DmInboxRuntimeError::InvalidRelayUrl { relay_index })?;
        if !matches!(parsed.scheme(), "ws" | "wss")
            || parsed.host_str().is_none()
            || parsed.fragment().is_some()
        {
            return Err(DmInboxRuntimeError::InvalidRelayUrl { relay_index });
        }
        if !relay_identities.insert(parsed.to_string()) {
            return Err(DmInboxRuntimeError::DuplicateRelay { relay_index });
        }
    }

    Ok(())
}

async fn wait_for_authentication(
    pool: &mut RelayPool,
    relay_count: usize,
    recipient_public_key: &str,
    authentication_timeout: Duration,
) -> Result<HashSet<usize>, DmInboxRuntimeError> {
    let deadline = Instant::now() + authentication_timeout;
    let mut authenticated_relays = HashSet::with_capacity(relay_count);

    while authenticated_relays.len() < relay_count {
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            return Err(DmInboxRuntimeError::AuthenticationTimeout {
                authenticated: authenticated_relays.len(),
                required: relay_count,
            });
        }

        let notification = match timeout(remaining, pool.next_notification()).await {
            Ok(Some(notification)) => notification,
            Ok(None) => return Err(DmInboxRuntimeError::Stopped),
            Err(_) => {
                return Err(DmInboxRuntimeError::AuthenticationTimeout {
                    authenticated: authenticated_relays.len(),
                    required: relay_count,
                });
            }
        };
        let relay_index = notification.relay_index;

        match notification.notification {
            RelayNotification::Authenticated { public_key } => {
                if public_key != recipient_public_key {
                    return Err(DmInboxRuntimeError::UnexpectedAuthenticationIdentity {
                        relay_index,
                        public_key,
                    });
                }
                authenticated_relays.insert(relay_index);
            }
            RelayNotification::AuthenticationRejected { message, .. } => {
                authenticated_relays.remove(&relay_index);
                return Err(DmInboxRuntimeError::AuthenticationRejected {
                    relay_index,
                    message,
                });
            }
            RelayNotification::Connected
            | RelayNotification::Disconnected
            | RelayNotification::AuthChallenge(_) => {
                authenticated_relays.remove(&relay_index);
            }
            RelayNotification::Event { .. }
            | RelayNotification::EndOfStoredEvents { .. }
            | RelayNotification::Closed { .. }
            | RelayNotification::Notice(_) => {}
        }
    }

    Ok(authenticated_relays)
}
