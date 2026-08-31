use crate::core_error::CoreError;
use omachat_crypto::{DisplayName, GlobalHandle};
use omachat_proto::geohash::Geohash;
use omachat_store::RequestedProvider;
use serde::Deserialize;
use std::{collections::HashSet, fs, path::Path};

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

#[derive(Clone, Debug, Default, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct DaemonConfig {
    pub storage_provider: StorageProviderConfig,
    pub relays: Vec<String>,
    pub dm_relays: Vec<String>,
    pub joined_geohashes: Vec<String>,
    /// Candidate global account handle. This remains local-only until a
    /// verified central-registry receipt is stored.
    pub account_handle: Option<String>,
    pub account_display_name: Option<String>,
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
        for geohash in &self.joined_geohashes {
            Geohash::parse(geohash).map_err(|_| CoreError::InvalidConfig)?;
        }
        if let Some(handle) = &self.account_handle {
            GlobalHandle::parse(handle).map_err(|_| CoreError::InvalidConfig)?;
        }
        if let Some(display_name) = &self.account_display_name {
            DisplayName::parse(display_name).map_err(|_| CoreError::InvalidConfig)?;
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
