use crate::core_error::CoreError;
use ed25519_dalek::VerifyingKey;
use omachat_crypto::{DisplayName, GlobalHandle};
use omachat_proto::geohash::Geohash;
use omachat_registry_transport::RegistryWebSocketTransport;
use omachat_store::RequestedProvider;
use serde::Deserialize;
use std::{collections::HashSet, fs, path::Path};

/// Wire and evidence contract expected from the configured registry endpoint.
#[derive(Clone, Copy, Debug, Default, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "kebab-case")]
pub enum RegistryProtocol {
    /// Existing account-root-only claim and receipt protocol.
    #[default]
    RootClaimV2,
    /// Root claim plus independently signed Nostr-principal proof protocol.
    PrincipalProofV1,
}

#[derive(Clone, Copy, Debug, Default, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum StorageProviderConfig {
    #[default]
    Auto,
    SecretService,
    File,
}
impl From<StorageProviderConfig> for RequestedProvider {
    fn from(value: StorageProviderConfig) -> Self {
        match value {
            StorageProviderConfig::Auto => Self::Auto,
            StorageProviderConfig::SecretService => Self::SecretService,
            StorageProviderConfig::File => Self::File,
        }
    }
}

/// Client-side trust and freshness policy for the authoritative handle registry.
///
/// The public key is pinned independently from the endpoint so DNS or TLS
/// compromise cannot replace signed registry evidence.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct RegistryClientConfig {
    pub endpoint: String,
    pub pinned_public_key: String,
    pub max_age_seconds: u64,
    /// Omission preserves the existing root-claim-v2 behavior.
    #[serde(default)]
    pub protocol: RegistryProtocol,
}

impl RegistryClientConfig {
    pub fn pinned_public_key_bytes(&self) -> Result<[u8; 32], CoreError> {
        let mut public_key = [0_u8; 32];
        hex::decode_to_slice(&self.pinned_public_key, &mut public_key)
            .map_err(|_| CoreError::InvalidConfig)?;
        let verifying_key =
            VerifyingKey::from_bytes(&public_key).map_err(|_| CoreError::InvalidConfig)?;
        if verifying_key.is_weak() {
            return Err(CoreError::InvalidConfig);
        }
        Ok(public_key)
    }

    fn validate(&self) -> Result<(), CoreError> {
        RegistryWebSocketTransport::new(&self.endpoint).map_err(|_| CoreError::InvalidConfig)?;
        self.pinned_public_key_bytes()?;
        if self.max_age_seconds == 0 {
            return Err(CoreError::InvalidConfig);
        }
        Ok(())
    }
}

/// Explicit relay and quorum policy for publishing this principal's kind-0
/// profile metadata. Absence keeps profile publication disabled.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct ProfilePublicationConfig {
    pub relays: Vec<String>,
    pub required_acknowledgements: usize,
}

impl ProfilePublicationConfig {
    fn validate(&self) -> Result<(), CoreError> {
        if self.relays.is_empty()
            || self.relays.len() > 16
            || self.required_acknowledgements == 0
            || self.required_acknowledgements > self.relays.len()
        {
            return Err(CoreError::InvalidConfig);
        }
        let mut canonical_relays = HashSet::with_capacity(self.relays.len());
        for relay in &self.relays {
            let url = url::Url::parse(relay).map_err(|_| CoreError::InvalidConfig)?;
            let secure = url.scheme() == "wss";
            let numeric_loopback = url.scheme() == "ws"
                && match url.host() {
                    Some(url::Host::Ipv4(address)) => address.is_loopback(),
                    Some(url::Host::Ipv6(address)) => address.is_loopback(),
                    _ => false,
                };
            if (!secure && !numeric_loopback)
                || url.host_str().is_none()
                || url.port_or_known_default().is_none()
                || !url.username().is_empty()
                || url.password().is_some()
                || url.query().is_some()
                || url.fragment().is_some()
                || !canonical_relays.insert(url.to_string())
            {
                return Err(CoreError::InvalidConfig);
            }
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Default, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct DaemonConfig {
    pub storage_provider: StorageProviderConfig,
    pub relays: Vec<String>,
    pub dm_relays: Vec<String>,
    /// Explicit profile publication policy. Omission is a truthful disabled
    /// state and never inherits geochat or private-message relays.
    pub profile_publication: Option<ProfilePublicationConfig>,
    pub joined_geohashes: Vec<String>,
    /// Candidate global account handle. This remains local-only until a
    /// verified central-registry receipt is stored.
    pub account_handle: Option<String>,
    pub account_display_name: Option<String>,
    /// Optional authoritative-registry client. Absence means local-only
    /// handles and must never be interpreted as a failed global claim.
    pub registry: Option<RegistryClientConfig>,
    /// Public geohash-chat nickname. This is deliberately independent from
    /// the persistent global account profile.
    pub nickname: Option<String>,
}

impl DaemonConfig {
    pub fn load(path: impl AsRef<Path>) -> Result<Self, CoreError> {
        let bytes = fs::read(path).map_err(CoreError::Io)?;
        let config: Self = serde_json::from_slice(&bytes).map_err(|_| CoreError::InvalidConfig)?;
        config.validate()?;
        Ok(config)
    }

    pub(crate) fn validate(&self) -> Result<(), CoreError> {
        for relay in &self.relays {
            let url = url::Url::parse(relay).map_err(|_| CoreError::InvalidConfig)?;
            if !matches!(url.scheme(), "ws" | "wss") {
                return Err(CoreError::InvalidConfig);
            }
        }
        if self.dm_relays.len() > 16 {
            return Err(CoreError::InvalidConfig);
        }
        let mut private_relays = HashSet::with_capacity(self.dm_relays.len());
        for relay in &self.dm_relays {
            let url = url::Url::parse(relay).map_err(|_| CoreError::InvalidConfig)?;
            if !matches!(url.scheme(), "ws" | "wss")
                || url.host_str().is_none()
                || !url.username().is_empty()
                || url.password().is_some()
                || url.fragment().is_some()
                || !private_relays.insert(url.to_string())
            {
                return Err(CoreError::InvalidConfig);
            }
        }
        if let Some(profile_publication) = &self.profile_publication {
            profile_publication.validate()?;
        }
        for geohash in &self.joined_geohashes {
            Geohash::parse(geohash).map_err(|_| CoreError::InvalidConfig)?;
        }
        if let Some(handle) = &self.account_handle {
            GlobalHandle::parse(handle).map_err(|_| CoreError::InvalidConfig)?;
        }
        if let Some(display_name) = &self.account_display_name {
            DisplayName::parse(display_name).map_err(|_| CoreError::InvalidConfig)?;
        }
        if let Some(registry) = &self.registry {
            registry.validate()?;
        }
        if self
            .nickname
            .as_ref()
            .is_some_and(|nickname| nickname.trim().is_empty() || nickname.len() > 64)
        {
            return Err(CoreError::InvalidConfig);
        }
        Ok(())
    }
}
