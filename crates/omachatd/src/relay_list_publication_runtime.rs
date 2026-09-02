use std::{error::Error, fmt, sync::Arc};

use omachat_nostr::{
    auth::RelayAuthSigner,
    discovery::{RelayDiscoveryLimits, RelayList, RelayPreference, parse_nip65_relay_list},
    event::{EventLimits, SignedEvent},
    relay_list::create_nip65_relay_list,
};
use omachat_store::SealedStore;
use tokio::sync::Mutex;

use crate::{
    NostrRelayListPublisherConfig, NostrRelayListPublisherError, NostrRelayListPublisherService,
    RelayListPublicationConfig, RelayListPublicationCoordinator,
    RelayListPublicationCoordinatorError, RelayListPublicationIntentError,
    RelayListPublicationIntentState, RelayListPublicationIntentStore, RelayListPublicationOutcome,
};

pub struct RelayListPublicationRuntime {
    expected_public_key: [u8; 32],
    preferences: Vec<RelayPreference>,
    required_acknowledgements: usize,
    event_limits: EventLimits,
    relay_limits: RelayDiscoveryLimits,
    coordinator: RelayListPublicationCoordinator,
    publisher: NostrRelayListPublisherService,
    operation: Mutex<()>,
}

impl RelayListPublicationRuntime {
    pub fn spawn(
        auth_signer: RelayAuthSigner,
        policy: &RelayListPublicationConfig,
        publisher_config: NostrRelayListPublisherConfig,
    ) -> Result<Self, RelayListPublicationRuntimeError> {
        let canonical = policy
            .canonical_relays()
            .map_err(|_| RelayListPublicationRuntimeError::InvalidPolicy)?;
        let preferences = canonical
            .into_iter()
            .map(|relay| RelayPreference {
                url: relay.url,
                read: relay.read,
                write: relay.write,
            })
            .collect::<Vec<_>>();
        let write_relays = preferences.iter().filter(|relay| relay.write).count();
        if publisher_config.max_relays < write_relays {
            return Err(RelayListPublicationRuntimeError::InvalidPolicy);
        }
        let expected_public_key = *auth_signer.public_key();
        let event_limits = publisher_config.event_limits;
        let relay_limits = RelayDiscoveryLimits {
            max_relays: publisher_config.max_relays,
            ..RelayDiscoveryLimits::default()
        };
        let publisher = NostrRelayListPublisherService::spawn(auth_signer, publisher_config)?;
        let coordinator = RelayListPublicationCoordinator::new(
            Arc::new(publisher.handle()),
            event_limits,
            relay_limits,
        );
        Ok(Self {
            expected_public_key,
            preferences,
            required_acknowledgements: policy.required_acknowledgements,
            event_limits,
            relay_limits,
            coordinator,
            publisher,
            operation: Mutex::new(()),
        })
    }

    pub fn create_event(
        &self,
        secret_key: &[u8; 32],
        created_at: u64,
    ) -> Result<SignedEvent, RelayListPublicationRuntimeError> {
        let event = create_nip65_relay_list(
            secret_key,
            created_at,
            &self.preferences,
            &self.event_limits,
            &self.relay_limits,
        )
        .map_err(RelayListPublicationRuntimeError::EventCreation)?;
        self.validate_event_policy(&event, created_at)?;
        Ok(event)
    }

    pub async fn publish(
        &self,
        store: &SealedStore,
        event: &SignedEvent,
        now: u64,
    ) -> Result<RelayListPublicationOutcome, RelayListPublicationRuntimeError> {
        let _operation = self.operation.lock().await;
        self.validate_event_policy(event, now)?;
        self.coordinator
            .publish(
                store,
                event,
                &self.expected_public_key,
                self.required_acknowledgements,
                now,
            )
            .await
            .map_err(Into::into)
    }

    pub async fn resume(
        &self,
        store: &SealedStore,
        now: u64,
    ) -> Result<Option<RelayListPublicationOutcome>, RelayListPublicationRuntimeError> {
        let _operation = self.operation.lock().await;
        let intents = RelayListPublicationIntentStore::new(store);
        match intents.load(now, &self.event_limits, &self.relay_limits)? {
            RelayListPublicationIntentState::Missing => Ok(None),
            RelayListPublicationIntentState::Pending(pending) => {
                self.validate_event_policy(pending.event(), now)?;
                self.coordinator
                    .resume(store, now)
                    .await
                    .map_err(Into::into)
            }
        }
    }

    pub async fn shutdown(self) -> Result<(), RelayListPublicationRuntimeError> {
        self.publisher.shutdown().await.map_err(Into::into)
    }

    pub fn expected_public_key(&self) -> &[u8; 32] {
        &self.expected_public_key
    }

    pub fn preferences(&self) -> &[RelayPreference] {
        &self.preferences
    }

    pub fn required_acknowledgements(&self) -> usize {
        self.required_acknowledgements
    }

    fn validate_event_policy(
        &self,
        event: &SignedEvent,
        now: u64,
    ) -> Result<RelayList, RelayListPublicationRuntimeError> {
        if event.pubkey != hex::encode(self.expected_public_key) {
            return Err(RelayListPublicationRuntimeError::PolicyMismatch);
        }
        let relay_list = parse_nip65_relay_list(event, now, &self.event_limits, &self.relay_limits)
            .map_err(|_| RelayListPublicationRuntimeError::PolicyMismatch)?;
        if relay_list.relays != self.preferences {
            return Err(RelayListPublicationRuntimeError::PolicyMismatch);
        }
        Ok(relay_list)
    }
}

#[derive(Debug)]
pub enum RelayListPublicationRuntimeError {
    InvalidPolicy,
    EventCreation(omachat_nostr::relay_list::RelayListPublicationError),
    PolicyMismatch,
    Intent(RelayListPublicationIntentError),
    Coordinator(RelayListPublicationCoordinatorError),
    Publisher(NostrRelayListPublisherError),
}

impl fmt::Display for RelayListPublicationRuntimeError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidPolicy => formatter.write_str("invalid NIP-65 publication policy"),
            Self::EventCreation(error) => {
                write!(formatter, "NIP-65 event creation failed: {error}")
            }
            Self::PolicyMismatch => {
                formatter.write_str("NIP-65 event does not match configured publication policy")
            }
            Self::Intent(error) => write!(formatter, "NIP-65 publication intent failed: {error}"),
            Self::Coordinator(error) => {
                write!(formatter, "NIP-65 publication coordination failed: {error}")
            }
            Self::Publisher(error) => write!(formatter, "NIP-65 publisher failed: {error}"),
        }
    }
}

impl Error for RelayListPublicationRuntimeError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Intent(error) => Some(error),
            Self::Coordinator(error) => Some(error),
            Self::Publisher(error) => Some(error),
            Self::EventCreation(error) => Some(error),
            Self::InvalidPolicy | Self::PolicyMismatch => None,
        }
    }
}

impl From<RelayListPublicationIntentError> for RelayListPublicationRuntimeError {
    fn from(error: RelayListPublicationIntentError) -> Self {
        Self::Intent(error)
    }
}

impl From<RelayListPublicationCoordinatorError> for RelayListPublicationRuntimeError {
    fn from(error: RelayListPublicationCoordinatorError) -> Self {
        Self::Coordinator(error)
    }
}

impl From<NostrRelayListPublisherError> for RelayListPublicationRuntimeError {
    fn from(error: NostrRelayListPublisherError) -> Self {
        Self::Publisher(error)
    }
}
