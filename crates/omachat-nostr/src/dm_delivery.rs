//! NIP-42-authenticated delivery of a verified NIP-17 publication plan.

use crate::{
    auth::RelayAuthSigner,
    inbox::DmPublishPlan,
    pool::{PoolPublishResult, RelayPool, RelayPoolConfig, RelayPoolError},
    relay::{RelayConfig, RelayNotification, RelayRoute},
};
use std::{
    collections::HashSet,
    error::Error,
    fmt,
    time::{Duration, Instant},
};

/// Owns every relay task used for one recipient-specific DM delivery.
pub struct AuthenticatedDmDelivery {
    pool: RelayPool,
    plan: DmPublishPlan,
    authentication: AuthenticatedRelayState,
}

impl AuthenticatedDmDelivery {
    /// Spawn exactly the relays named by the verified inbox plan.
    pub fn spawn(
        plan: DmPublishPlan,
        route: RelayRoute,
        auth_signer: RelayAuthSigner,
    ) -> Result<Self, DmDeliveryError> {
        let authentication_public_key = hex::encode(auth_signer.public_key());
        if authentication_public_key == plan.event.pubkey {
            return Err(DmDeliveryError::EphemeralAuthenticationIdentity);
        }
        if plan.relay_urls.is_empty()
            || plan.required_acknowledgements == 0
            || plan.required_acknowledgements > plan.relay_urls.len()
        {
            return Err(DmDeliveryError::InvalidPlan);
        }
        let relay_configs = plan
            .relay_urls
            .iter()
            .map(|url| {
                let mut config = RelayConfig::new(url.clone(), route.clone());
                config.auth = Some(auth_signer.clone());
                config
            })
            .collect();
        let pool = RelayPool::spawn(
            relay_configs,
            RelayPoolConfig {
                acknowledgement_threshold: plan.required_acknowledgements,
                ..RelayPoolConfig::default()
            },
        )?;
        Ok(Self {
            pool,
            plan,
            authentication: AuthenticatedRelayState::new(authentication_public_key),
        })
    }

    /// Wait until enough currently connected relays authenticate the expected
    /// real principal. A wrapper's one-time key is never accepted here.
    pub async fn wait_until_authenticated(
        &mut self,
        timeout: Duration,
    ) -> Result<(), DmDeliveryError> {
        if timeout.is_zero() {
            return Err(DmDeliveryError::AuthenticationTimeout);
        }
        let deadline = Instant::now() + timeout;
        while self.authentication.authenticated.len() < self.plan.required_acknowledgements {
            let remaining = deadline.saturating_duration_since(Instant::now());
            if remaining.is_zero() {
                return Err(DmDeliveryError::AuthenticationTimeout);
            }
            let notification = tokio::time::timeout(remaining, self.pool.next_notification())
                .await
                .map_err(|_| DmDeliveryError::AuthenticationTimeout)?
                .ok_or(DmDeliveryError::PoolStopped)?;
            self.authentication
                .apply(notification.relay_index, &notification.notification)?;
        }
        Ok(())
    }

    /// Publish only to relays that authenticated the expected principal and
    /// require the original inbox plan's acknowledgement threshold.
    pub async fn publish(&self) -> Result<PoolPublishResult, DmDeliveryError> {
        Ok(self
            .pool
            .publish_to_indices(
                self.plan.event.clone(),
                &self.authentication.authenticated,
                self.plan.required_acknowledgements,
            )
            .await?)
    }

    /// Abort if needed, then await every owned relay task.
    pub async fn shutdown(self) -> Vec<Result<(), crate::relay::RelayError>> {
        self.pool.shutdown().await
    }
}

#[derive(Debug)]
struct AuthenticatedRelayState {
    expected_public_key: String,
    authenticated: HashSet<usize>,
}

impl AuthenticatedRelayState {
    fn new(expected_public_key: String) -> Self {
        Self {
            expected_public_key,
            authenticated: HashSet::new(),
        }
    }

    fn apply(
        &mut self,
        relay_index: usize,
        notification: &RelayNotification,
    ) -> Result<(), DmDeliveryError> {
        match notification {
            RelayNotification::Authenticated { public_key } => {
                if public_key != &self.expected_public_key {
                    return Err(DmDeliveryError::UnexpectedAuthenticatedPrincipal);
                }
                self.authenticated.insert(relay_index);
            }
            RelayNotification::AuthenticationRejected {
                public_key,
                message,
            } => {
                self.authenticated.remove(&relay_index);
                if public_key == &self.expected_public_key {
                    return Err(DmDeliveryError::AuthenticationRejected(message.clone()));
                }
                return Err(DmDeliveryError::UnexpectedAuthenticatedPrincipal);
            }
            RelayNotification::Disconnected => {
                self.authenticated.remove(&relay_index);
            }
            _ => {}
        }
        Ok(())
    }
}

#[derive(Debug)]
pub enum DmDeliveryError {
    InvalidPlan,
    EphemeralAuthenticationIdentity,
    Pool(RelayPoolError),
    AuthenticationTimeout,
    AuthenticationRejected(String),
    UnexpectedAuthenticatedPrincipal,
    PoolStopped,
}

impl From<RelayPoolError> for DmDeliveryError {
    fn from(error: RelayPoolError) -> Self {
        Self::Pool(error)
    }
}

impl fmt::Display for DmDeliveryError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidPlan => formatter.write_str("invalid DM publication plan"),
            Self::EphemeralAuthenticationIdentity => formatter
                .write_str("gift-wrap ephemeral key cannot authenticate the relay connection"),
            Self::Pool(error) => write!(formatter, "relay pool failure: {error}"),
            Self::AuthenticationTimeout => {
                formatter.write_str("relay authentication threshold timed out")
            }
            Self::AuthenticationRejected(message) => {
                write!(formatter, "relay rejected authentication: {message}")
            }
            Self::UnexpectedAuthenticatedPrincipal => {
                formatter.write_str("relay authenticated an unexpected principal")
            }
            Self::PoolStopped => {
                formatter.write_str("relay pool stopped before authentication completed")
            }
        }
    }
}

impl Error for DmDeliveryError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Pool(error) => Some(error),
            _ => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_the_expected_principal_becomes_eligible() {
        let expected = "11".repeat(32);
        let mut state = AuthenticatedRelayState::new(expected.clone());
        state
            .apply(
                1,
                &RelayNotification::Authenticated {
                    public_key: expected,
                },
            )
            .unwrap();
        assert_eq!(state.authenticated, HashSet::from([1]));
        assert!(matches!(
            state.apply(
                2,
                &RelayNotification::Authenticated {
                    public_key: "22".repeat(32),
                },
            ),
            Err(DmDeliveryError::UnexpectedAuthenticatedPrincipal)
        ));
        assert_eq!(state.authenticated, HashSet::from([1]));
    }

    #[test]
    fn rejection_and_disconnect_remove_eligibility() {
        let expected = "11".repeat(32);
        let mut state = AuthenticatedRelayState::new(expected.clone());
        state
            .apply(
                0,
                &RelayNotification::Authenticated {
                    public_key: expected.clone(),
                },
            )
            .unwrap();
        state.apply(0, &RelayNotification::Disconnected).unwrap();
        assert!(state.authenticated.is_empty());

        state
            .apply(
                0,
                &RelayNotification::Authenticated {
                    public_key: expected.clone(),
                },
            )
            .unwrap();
        assert!(matches!(
            state.apply(
                0,
                &RelayNotification::AuthenticationRejected {
                    public_key: expected,
                    message: "restricted".to_owned(),
                },
            ),
            Err(DmDeliveryError::AuthenticationRejected(message)) if message == "restricted"
        ));
        assert!(state.authenticated.is_empty());
    }
}
