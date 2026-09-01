use std::{collections::BTreeSet, error::Error, fmt, future::Future, pin::Pin, sync::Arc};

use omachat_nostr::{
    discovery::RelayDiscoveryLimits,
    event::{EventLimits, SignedEvent},
};
use omachat_store::SealedStore;
use tokio::sync::Mutex;

use crate::{
    RelayListPublicationIntentError, RelayListPublicationIntentState,
    RelayListPublicationIntentStore, RelayListPublicationMutation,
};

pub type RelayListPublishFuture<'a> =
    Pin<Box<dyn Future<Output = Vec<RelayListRelayResult>> + Send + 'a>>;

pub trait RelayListPublisher: Send + Sync {
    fn publish<'a>(
        &'a self,
        event: SignedEvent,
        relay_urls: Vec<String>,
    ) -> RelayListPublishFuture<'a>;
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RelayListRelayStatus {
    Acknowledged,
    Rejected,
    Failed,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RelayListRelayResult {
    pub relay_url: String,
    pub status: RelayListRelayStatus,
}

pub struct RelayListPublicationCoordinator {
    publisher: Arc<dyn RelayListPublisher>,
    event_limits: EventLimits,
    relay_limits: RelayDiscoveryLimits,
    operation: Mutex<()>,
}

impl RelayListPublicationCoordinator {
    pub fn new(
        publisher: Arc<dyn RelayListPublisher>,
        event_limits: EventLimits,
        relay_limits: RelayDiscoveryLimits,
    ) -> Self {
        Self {
            publisher,
            event_limits,
            relay_limits,
            operation: Mutex::new(()),
        }
    }

    pub async fn publish(
        &self,
        store: &SealedStore,
        event: &SignedEvent,
        expected_public_key: &[u8; 32],
        required_acknowledgements: usize,
        now: u64,
    ) -> Result<RelayListPublicationOutcome, RelayListPublicationCoordinatorError> {
        let _operation = self.operation.lock().await;
        let intents = RelayListPublicationIntentStore::new(store);
        let mutation = intents.prepare(
            event,
            expected_public_key,
            required_acknowledgements,
            now,
            &self.event_limits,
            &self.relay_limits,
        )?;
        let source = match mutation {
            RelayListPublicationMutation::Stored => RelayListPublicationSource::New,
            RelayListPublicationMutation::Unchanged => RelayListPublicationSource::SealedReplay,
        };
        self.publish_pending(&intents, source, now).await
    }

    pub async fn resume(
        &self,
        store: &SealedStore,
        now: u64,
    ) -> Result<Option<RelayListPublicationOutcome>, RelayListPublicationCoordinatorError> {
        let _operation = self.operation.lock().await;
        let intents = RelayListPublicationIntentStore::new(store);
        match intents.load(now, &self.event_limits, &self.relay_limits)? {
            RelayListPublicationIntentState::Missing => Ok(None),
            RelayListPublicationIntentState::Pending(_) => self
                .publish_pending(&intents, RelayListPublicationSource::SealedReplay, now)
                .await
                .map(Some),
        }
    }

    async fn publish_pending(
        &self,
        intents: &RelayListPublicationIntentStore<'_>,
        source: RelayListPublicationSource,
        now: u64,
    ) -> Result<RelayListPublicationOutcome, RelayListPublicationCoordinatorError> {
        let RelayListPublicationIntentState::Pending(pending) =
            intents.load(now, &self.event_limits, &self.relay_limits)?
        else {
            return Err(RelayListPublicationCoordinatorError::MissingIntent);
        };
        let attempted_relays = pending
            .publication_relays()
            .iter()
            .filter(|relay| !pending.acknowledged_relays().contains(relay.as_str()))
            .cloned()
            .collect::<Vec<_>>();
        let results = self
            .publisher
            .publish(pending.event().clone(), attempted_relays.clone())
            .await;
        validate_transport_results(&attempted_relays, &results)?;

        let mut acknowledged_relays = pending
            .acknowledged_relays()
            .iter()
            .cloned()
            .collect::<Vec<_>>();
        let mut complete = false;
        for result in &results {
            if result.status != RelayListRelayStatus::Acknowledged {
                continue;
            }
            let progress = intents.acknowledge(
                &pending.event().id,
                &result.relay_url,
                now,
                &self.event_limits,
                &self.relay_limits,
            )?;
            acknowledged_relays = progress.acknowledged_relays;
            complete = progress.complete;
            if complete {
                break;
            }
        }
        let rejected_relays = results
            .iter()
            .filter(|result| result.status == RelayListRelayStatus::Rejected)
            .map(|result| result.relay_url.clone())
            .collect();
        let failed_relays = results
            .iter()
            .filter(|result| result.status == RelayListRelayStatus::Failed)
            .map(|result| result.relay_url.clone())
            .collect();
        Ok(RelayListPublicationOutcome {
            event_id: pending.event().id.clone(),
            public_key: pending.event().pubkey.clone(),
            status: if complete {
                RelayListPublicationOutcomeStatus::Complete
            } else {
                RelayListPublicationOutcomeStatus::Pending
            },
            source,
            attempted_relays,
            acknowledged_relays,
            rejected_relays,
            failed_relays,
            required_acknowledgements: pending.required_acknowledgements(),
        })
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RelayListPublicationOutcomeStatus {
    Pending,
    Complete,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RelayListPublicationSource {
    New,
    SealedReplay,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RelayListPublicationOutcome {
    pub event_id: String,
    pub public_key: String,
    pub status: RelayListPublicationOutcomeStatus,
    pub source: RelayListPublicationSource,
    pub attempted_relays: Vec<String>,
    pub acknowledged_relays: Vec<String>,
    pub rejected_relays: Vec<String>,
    pub failed_relays: Vec<String>,
    pub required_acknowledgements: usize,
}

#[derive(Debug)]
pub enum RelayListPublicationCoordinatorError {
    Intent(RelayListPublicationIntentError),
    MissingIntent,
    InvalidTransportResult,
}

impl fmt::Display for RelayListPublicationCoordinatorError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Intent(error) => write!(formatter, "NIP-65 publication intent failed: {error}"),
            Self::MissingIntent => formatter.write_str("NIP-65 publication intent disappeared"),
            Self::InvalidTransportResult => {
                formatter.write_str("NIP-65 publisher returned an invalid relay result set")
            }
        }
    }
}

impl Error for RelayListPublicationCoordinatorError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Intent(error) => Some(error),
            Self::MissingIntent | Self::InvalidTransportResult => None,
        }
    }
}

impl From<RelayListPublicationIntentError> for RelayListPublicationCoordinatorError {
    fn from(error: RelayListPublicationIntentError) -> Self {
        Self::Intent(error)
    }
}

fn validate_transport_results(
    attempted_relays: &[String],
    results: &[RelayListRelayResult],
) -> Result<(), RelayListPublicationCoordinatorError> {
    if attempted_relays.len() != results.len() {
        return Err(RelayListPublicationCoordinatorError::InvalidTransportResult);
    }
    let expected = attempted_relays.iter().collect::<BTreeSet<_>>();
    let actual = results
        .iter()
        .map(|result| &result.relay_url)
        .collect::<BTreeSet<_>>();
    if expected.len() != attempted_relays.len()
        || actual.len() != results.len()
        || expected != actual
    {
        return Err(RelayListPublicationCoordinatorError::InvalidTransportResult);
    }
    Ok(())
}
