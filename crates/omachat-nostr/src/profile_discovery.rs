use std::{error::Error, fmt, time::Duration};

use crate::{
    auth::RelayAuthSigner,
    event::{EventLimits, SignedEvent},
    profile_metadata::PROFILE_METADATA_KIND,
    profile_verification::{
        ProfileVerificationError, VerifiedNostrProfile, verify_profile_metadata,
    },
    relay::{RelayAuthenticationPolicy, RelayConfig},
    replaceable_discovery::{ReplaceableDiscoveryConfig, discover_replaceable_event},
};

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ProfileDiscoveryConfig {
    pub authentication_timeout: Duration,
    pub authentication_policy: RelayAuthenticationPolicy,
    pub challenge_settle_timeout: Duration,
    pub query_timeout: Duration,
    pub minimum_ready_relays: usize,
    pub subscription_id: String,
}

impl Default for ProfileDiscoveryConfig {
    fn default() -> Self {
        Self {
            authentication_timeout: Duration::from_secs(10),
            authentication_policy: RelayAuthenticationPolicy::AuthenticateWhenChallenged,
            challenge_settle_timeout: Duration::from_millis(100),
            query_timeout: Duration::from_secs(10),
            minimum_ready_relays: 1,
            subscription_id: "omachat-profile-discovery".into(),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ProfileDiscoveryResult {
    pub event: SignedEvent,
    pub profile: VerifiedNostrProfile,
    pub queried_relays: usize,
    pub completed_relays: usize,
}

pub async fn discover_profile_metadata(
    relay_configs: Vec<RelayConfig>,
    auth_signer: RelayAuthSigner,
    participant_public_key: &[u8; 32],
    now: u64,
    event_limits: &EventLimits,
    config: &ProfileDiscoveryConfig,
) -> Result<ProfileDiscoveryResult, ProfileDiscoveryError> {
    let transport_config = ReplaceableDiscoveryConfig {
        authentication_timeout: config.authentication_timeout,
        authentication_policy: config.authentication_policy,
        challenge_settle_timeout: config.challenge_settle_timeout,
        query_timeout: config.query_timeout,
        minimum_ready_relays: config.minimum_ready_relays,
        subscription_id: config.subscription_id.clone(),
    };
    let discovered = discover_replaceable_event(
        relay_configs,
        auth_signer,
        participant_public_key,
        PROFILE_METADATA_KIND,
        &transport_config,
        |event| verify_profile_metadata(event, participant_public_key, now, event_limits).is_ok(),
    )
    .await
    .map_err(|error| ProfileDiscoveryError::Transport(error.to_string()))?;
    let profile =
        verify_profile_metadata(&discovered.event, participant_public_key, now, event_limits)
            .map_err(ProfileDiscoveryError::Verification)?;
    Ok(ProfileDiscoveryResult {
        event: discovered.event,
        profile,
        queried_relays: discovered.queried_relays,
        completed_relays: discovered.completed_relays,
    })
}

#[derive(Debug)]
pub enum ProfileDiscoveryError {
    Transport(String),
    Verification(ProfileVerificationError),
}

impl fmt::Display for ProfileDiscoveryError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Transport(error) => write!(formatter, "profile discovery failed: {error}"),
            Self::Verification(error) => {
                write!(formatter, "selected profile failed verification: {error}")
            }
        }
    }
}

impl Error for ProfileDiscoveryError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Transport(_) => None,
            Self::Verification(error) => Some(error),
        }
    }
}
