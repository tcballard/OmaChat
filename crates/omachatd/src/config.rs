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
    pub(crate) fn validate(&self) -> Result<(), CoreError> {
        if self.relays.is_empty()
            || self.relays.len() > 16
            || self.required_acknowledgements == 0
            || self.required_acknowledgements > self.relays.len()
        {
            return Err(CoreError::InvalidConfig);
        }
        let mut canonical_relays = HashSet::with_capacity(self.relays.len());
        for relay in &self.relays {
            let canonical = canonical_publication_url(relay)?;
            if !canonical_relays.insert(canonical) {
                return Err(CoreError::InvalidConfig);
            }
        }
        Ok(())
    }

    pub(crate) fn canonical_relays(&self) -> Result<Vec<String>, CoreError> {
        self.validate()?;
        let mut relays = self
            .relays
            .iter()
            .map(|relay| {
                url::Url::parse(relay)
                    .map(|url| url.to_string())
                    .map_err(|_| CoreError::InvalidConfig)
            })
            .collect::<Result<Vec<_>, _>>()?;
        relays.sort_unstable();
        Ok(relays)
    }
}

/// One explicitly classified relay in this principal's NIP-65 kind-10002
/// advertisement. The relay remains reachability metadata, not identity or
/// handle authority.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct RelayListPublicationRelayConfig {
    pub url: String,
    pub read: bool,
    pub write: bool,
}

/// Explicit NIP-65 advertisement and publication policy. Absence keeps
/// relay-list publication disabled and never inherits bootstrap, geochat,
/// profile, or private-message relays.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct RelayListPublicationConfig {
    pub relays: Vec<RelayListPublicationRelayConfig>,
    pub required_acknowledgements: usize,
}

impl RelayListPublicationConfig {
    pub(crate) fn validate(&self) -> Result<(), CoreError> {
        if self.relays.is_empty() || self.relays.len() > 16 {
            return Err(CoreError::InvalidConfig);
        }
        let mut canonical_relays = HashSet::with_capacity(self.relays.len());
        let mut write_relays = 0;
        for relay in &self.relays {
            if !relay.read && !relay.write {
                return Err(CoreError::InvalidConfig);
            }
            let canonical = canonical_publication_url(&relay.url)?;
            if !canonical_relays.insert(canonical) {
                return Err(CoreError::InvalidConfig);
            }
            write_relays += usize::from(relay.write);
        }
        if self.required_acknowledgements == 0 || self.required_acknowledgements > write_relays {
            return Err(CoreError::InvalidConfig);
        }
        Ok(())
    }

    /// Return validated relay entries in deterministic canonical URL order.
    pub fn canonical_relays(&self) -> Result<Vec<RelayListPublicationRelayConfig>, CoreError> {
        self.validate()?;
        let mut relays = self
            .relays
            .iter()
            .map(|relay| {
                Ok(RelayListPublicationRelayConfig {
                    url: canonical_publication_url(&relay.url)?,
                    read: relay.read,
                    write: relay.write,
                })
            })
            .collect::<Result<Vec<_>, CoreError>>()?;
        relays.sort_unstable_by(|left, right| left.url.cmp(&right.url));
        Ok(relays)
    }
}

/// NIP-29 room relays. Each relay is bound to the signing identity its NIP-11
/// document declares and reduced independently; a URL change with the same
/// verified key is the same relay, the same group ID under another key is a
/// different room.
#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq)]
#[serde(default, deny_unknown_fields)]
pub struct RoomsConfig {
    /// Room relay URLs: `wss://` or numeric-loopback `ws://`, no credentials,
    /// query, or fragment.
    pub relays: Vec<String>,
    /// Rollback-resistant generation storage. File anchors remain the default;
    /// Secret Service must be selected explicitly.
    pub anchor_provider: RoomAnchorProviderConfig,
    /// Directory for room-state generation anchors. It must lie outside the
    /// daemon state directory; when omitted the daemon uses a sibling of the
    /// state directory named `<state>-anchors`.
    pub anchor_directory: Option<std::path::PathBuf>,
}

#[derive(Clone, Copy, Debug, Default, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "kebab-case")]
pub enum RoomAnchorProviderConfig {
    #[default]
    File,
    SecretService,
}

impl RoomsConfig {
    pub fn canonical_relays(&self) -> Result<Vec<String>, CoreError> {
        let mut relays = self
            .relays
            .iter()
            .map(|relay| canonical_publication_url(relay))
            .collect::<Result<Vec<_>, CoreError>>()?;
        relays.sort_unstable();
        relays.dedup();
        Ok(relays)
    }

    pub(crate) fn validate(&self) -> Result<(), CoreError> {
        if self.anchor_provider == RoomAnchorProviderConfig::SecretService
            && self.anchor_directory.is_some()
        {
            return Err(CoreError::InvalidConfig);
        }
        if self.relays.len() > 16 {
            return Err(CoreError::InvalidConfig);
        }
        let canonical = self.canonical_relays()?;
        if canonical.len() != self.relays.len() {
            return Err(CoreError::InvalidConfig);
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
    /// Opt-in pinned per-cell pools, isolated from the legacy relay list.
    pub geo_relays: Option<crate::GeoRelayConfig>,
    /// Explicit profile publication policy. Omission is a truthful disabled
    /// state and never inherits geochat or private-message relays.
    pub profile_publication: Option<ProfilePublicationConfig>,
    /// Explicit NIP-65 publication policy. Omission is a truthful disabled
    /// state and never inherits any other relay list.
    pub relay_list_publication: Option<RelayListPublicationConfig>,
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
    /// Optional NIP-29 room relays. Omission means no rooms; the geochat and
    /// private-message relay sets are never reused for rooms.
    pub rooms: Option<RoomsConfig>,
}

impl DaemonConfig {
    pub fn load(path: impl AsRef<Path>) -> Result<Self, CoreError> {
        let bytes = fs::read(path).map_err(CoreError::Io)?;
        let config: Self = serde_json::from_slice(&bytes).map_err(|_| CoreError::InvalidConfig)?;
        config.validate()?;
        Ok(config)
    }

    pub(crate) fn validate(&self) -> Result<(), CoreError> {
        if let Some(geo) = &self.geo_relays {
            geo.validate()?;
            if self.joined_geohashes.len() > crate::geo_relay_service::MAX_GEO_CELLS {
                return Err(CoreError::InvalidConfig);
            }
        }
        let mut geochat_relays = HashSet::with_capacity(self.relays.len());
        for relay in &self.relays {
            if !geochat_relays.insert(canonical_publication_url(relay)?) {
                return Err(CoreError::InvalidConfig);
            }
        }
        if self.dm_relays.len() > 16 {
            return Err(CoreError::InvalidConfig);
        }
        let mut private_relays = HashSet::with_capacity(self.dm_relays.len());
        for relay in &self.dm_relays {
            if !private_relays.insert(canonical_publication_url(relay)?) {
                return Err(CoreError::InvalidConfig);
            }
        }
        if let Some(profile_publication) = &self.profile_publication {
            profile_publication.validate()?;
        }
        if let Some(relay_list_publication) = &self.relay_list_publication {
            relay_list_publication.validate()?;
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
        if let Some(rooms) = &self.rooms {
            rooms.validate()?;
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

pub(crate) fn canonical_publication_url(raw: &str) -> Result<String, CoreError> {
    let url = url::Url::parse(raw).map_err(|_| CoreError::InvalidConfig)?;
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
    {
        return Err(CoreError::InvalidConfig);
    }
    Ok(url.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn room_anchor_provider_defaults_to_file() {
        let config: DaemonConfig =
            serde_json::from_str(r#"{"rooms":{"relays":["wss://rooms.example"]}}"#)
                .expect("config");
        assert_eq!(
            config.rooms.expect("rooms").anchor_provider,
            RoomAnchorProviderConfig::File
        );
    }

    #[test]
    fn secret_service_anchor_rejects_a_file_directory() {
        let config: DaemonConfig = serde_json::from_str(
            r#"{
                "rooms": {
                    "relays": ["wss://rooms.example"],
                    "anchor_provider": "secret-service",
                    "anchor_directory": "/tmp/ignored"
                }
            }"#,
        )
        .expect("config");
        assert!(matches!(config.validate(), Err(CoreError::InvalidConfig)));
    }
}
