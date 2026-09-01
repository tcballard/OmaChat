use std::{error::Error, fmt};

use omachat_nostr::{
    auth::RelayAuthSigner,
    event::{EventLimits, SignedEvent},
};
use omachat_store::SealedStore;

use crate::{
    ProfilePublicationConfig, ProfilePublicationIntentError, ProfilePublicationIntentStore,
    ProfilePublicationProgress, ProfilePublicationService, ProfilePublicationServiceConfig,
    ProfilePublicationServiceError,
};

/// Owns the sealed profile-publication transaction and its live relay pool.
///
/// Callers must retain this coordinator across cancelled operations and invoke
/// `shutdown` before erasing account state or terminating the daemon.
pub struct ProfilePublicationCoordinator<'store> {
    intents: ProfilePublicationIntentStore<'store>,
    relay_urls: Vec<String>,
    required_acknowledgements: usize,
    expected_public_key: [u8; 32],
    auth_signer: RelayAuthSigner,
    service_config: ProfilePublicationServiceConfig,
    service: Option<ProfilePublicationService>,
}

impl<'store> ProfilePublicationCoordinator<'store> {
    pub fn new(
        store: &'store SealedStore,
        config: &ProfilePublicationConfig,
        auth_signer: RelayAuthSigner,
        service_config: ProfilePublicationServiceConfig,
    ) -> Result<Self, ProfilePublicationCoordinatorError> {
        let relay_urls = config
            .canonical_relays()
            .map_err(|_| ProfilePublicationCoordinatorError::InvalidConfig)?;
        let expected_public_key = *auth_signer.public_key();
        Ok(Self {
            intents: ProfilePublicationIntentStore::new(store),
            relay_urls,
            required_acknowledgements: config.required_acknowledgements,
            expected_public_key,
            auth_signer,
            service_config,
            service: None,
        })
    }

    /// Seal a new exact event before attempting any relay publication.
    pub async fn publish(
        &mut self,
        event: &SignedEvent,
        now: u64,
        event_limits: &EventLimits,
    ) -> Result<ProfilePublicationProgress, ProfilePublicationCoordinatorError> {
        let pending = self.intents.prepare(
            event,
            &self.relay_urls,
            self.required_acknowledgements,
            &self.expected_public_key,
            now,
            event_limits,
        )?;
        self.drive(pending, now, event_limits).await
    }

    /// Resume the exact sealed event and relay progress, if one exists.
    pub async fn resume(
        &mut self,
        now: u64,
        event_limits: &EventLimits,
    ) -> Result<Option<ProfilePublicationProgress>, ProfilePublicationCoordinatorError> {
        let Some(pending) = self
            .intents
            .load(&self.expected_public_key, now, event_limits)?
        else {
            return Ok(None);
        };
        self.verify_policy(&pending)?;
        self.drive(pending, now, event_limits).await.map(Some)
    }

    /// Stop accepting relay work and join every owned connection actor.
    pub async fn shutdown(mut self) -> Result<(), ProfilePublicationCoordinatorError> {
        if let Some(service) = self.service.take() {
            service.shutdown().await?;
        }
        Ok(())
    }

    async fn drive(
        &mut self,
        pending: crate::PendingProfilePublication,
        now: u64,
        event_limits: &EventLimits,
    ) -> Result<ProfilePublicationProgress, ProfilePublicationCoordinatorError> {
        self.verify_policy(&pending)?;
        if self.service.is_none() {
            self.service = Some(ProfilePublicationService::spawn(
                pending.relay_urls(),
                self.auth_signer.clone(),
                self.service_config.clone(),
            )?);
        }
        let result = self
            .service
            .as_ref()
            .expect("profile publication service is owned")
            .handle()
            .publish(&pending)
            .await?;
        let accepted = result
            .outcomes
            .iter()
            .filter(|outcome| outcome.result.is_ok())
            .map(|outcome| outcome.relay_index)
            .collect::<Vec<_>>();
        Ok(self.intents.acknowledge(
            &pending.event().id,
            &accepted,
            &self.expected_public_key,
            now,
            event_limits,
        )?)
    }

    fn verify_policy(
        &self,
        pending: &crate::PendingProfilePublication,
    ) -> Result<(), ProfilePublicationCoordinatorError> {
        if pending.relay_urls() != self.relay_urls
            || pending.required_acknowledgements() != self.required_acknowledgements
        {
            return Err(ProfilePublicationCoordinatorError::PolicyMismatch);
        }
        Ok(())
    }
}

#[derive(Debug)]
pub enum ProfilePublicationCoordinatorError {
    InvalidConfig,
    PolicyMismatch,
    Intent(ProfilePublicationIntentError),
    Service(ProfilePublicationServiceError),
}

impl fmt::Display for ProfilePublicationCoordinatorError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidConfig => formatter.write_str("profile publication config is invalid"),
            Self::PolicyMismatch => formatter
                .write_str("sealed profile publication policy does not match daemon config"),
            Self::Intent(error) => write!(formatter, "profile publication intent failed: {error}"),
            Self::Service(error) => {
                write!(formatter, "profile publication service failed: {error}")
            }
        }
    }
}

impl Error for ProfilePublicationCoordinatorError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Intent(error) => Some(error),
            Self::Service(error) => Some(error),
            Self::InvalidConfig | Self::PolicyMismatch => None,
        }
    }
}

impl From<ProfilePublicationIntentError> for ProfilePublicationCoordinatorError {
    fn from(error: ProfilePublicationIntentError) -> Self {
        Self::Intent(error)
    }
}

impl From<ProfilePublicationServiceError> for ProfilePublicationCoordinatorError {
    fn from(error: ProfilePublicationServiceError) -> Self {
        Self::Service(error)
    }
}
