use crate::CoreError;
use ed25519_dalek::VerifyingKey;
use omachat_store::RequestedProvider;
use serde::Deserialize;
use std::{fs, path::Path};
#[derive(Clone, Copy, Debug, Default, Deserialize, Eq, PartialEq)]
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

/// Hosted server transport (ADR 0007). The server public key is pinned
/// independently from the URL so a rogue or mis-issued TLS certificate cannot
/// impersonate the server during authentication. Omission keeps the hosted
/// transport disabled; a change requires a daemon restart.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct HostedConfig {
    /// `wss://` URL, or numeric-loopback `ws://` for local testing.
    pub url: String,
    /// Hex-encoded Ed25519 public key of the server, obtained out of band.
    pub pinned_server_public_key: String,
    /// Display name sent when this device registers a new account. The
    /// server keeps the first name it stored for the account.
    #[serde(default)]
    pub display_name: Option<String>,
    /// Invite code sent when this device registers on an invite-only server.
    #[serde(default)]
    pub invite_code: Option<String>,
}

impl HostedConfig {
    pub fn pinned_server_public_key_bytes(&self) -> Result<[u8; 32], CoreError> {
        let mut public_key = [0_u8; 32];
        hex::decode_to_slice(&self.pinned_server_public_key, &mut public_key)
            .map_err(|_| CoreError::InvalidConfig)?;
        let verifying_key =
            VerifyingKey::from_bytes(&public_key).map_err(|_| CoreError::InvalidConfig)?;
        if verifying_key.is_weak() {
            return Err(CoreError::InvalidConfig);
        }
        Ok(public_key)
    }

    pub fn canonical_url(&self) -> Result<String, CoreError> {
        canonical_publication_url(&self.url)
    }

    pub(crate) fn validate(&self) -> Result<(), CoreError> {
        self.canonical_url()?;
        self.pinned_server_public_key_bytes()?;
        if let Some(display_name) = &self.display_name {
            omachat_proto::hosted::validate_name(display_name)
                .map_err(|_| CoreError::InvalidConfig)?;
        }
        if self.invite_code.as_ref().is_some_and(|code| {
            code.is_empty()
                || code.len() > omachat_proto::hosted::MAX_INVITE_CODE_BYTES
                || code.chars().any(char::is_control)
        }) {
            return Err(CoreError::InvalidConfig);
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Default, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct DaemonConfig {
    pub storage_provider: StorageProviderConfig,
    pub hosted: Option<HostedConfig>,
}
impl DaemonConfig {
    pub fn load(path: impl AsRef<Path>) -> Result<Self, CoreError> {
        let bytes = fs::read(path).map_err(CoreError::Io)?;
        let config: Self = serde_json::from_slice(&bytes).map_err(|_| CoreError::InvalidConfig)?;
        config.validate()?;
        Ok(config)
    }
    pub(crate) fn validate(&self) -> Result<(), CoreError> {
        if let Some(hosted) = &self.hosted {
            hosted.validate()?;
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
    fn hosted_config_requires_a_secure_url_and_a_valid_pin() {
        let key = hex::encode(
            ed25519_dalek::SigningKey::from_bytes(&[7_u8; 32])
                .verifying_key()
                .to_bytes(),
        );
        let valid: DaemonConfig = serde_json::from_str(&format!(
            r#"{{"hosted":{{"url":"wss://chat.example","pinned_server_public_key":"{key}","display_name":"Tom","invite_code":"welcome"}}}}"#
        ))
        .expect("config");
        valid.validate().expect("valid hosted config");
        for bad in [
            format!(
                r#"{{"hosted":{{"url":"ws://chat.example","pinned_server_public_key":"{key}"}}}}"#
            ),
            format!(
                r#"{{"hosted":{{"url":"wss://chat.example?x=1","pinned_server_public_key":"{key}"}}}}"#
            ),
            r#"{"hosted":{"url":"wss://chat.example","pinned_server_public_key":"00"}}"#.to_owned(),
            format!(
                r#"{{"hosted":{{"url":"wss://chat.example","pinned_server_public_key":"{key}","display_name":" padded"}}}}"#
            ),
            format!(
                r#"{{"hosted":{{"url":"wss://chat.example","pinned_server_public_key":"{key}","invite_code":""}}}}"#
            ),
            format!(
                r#"{{"hosted":{{"url":"wss://chat.example","pinned_server_public_key":"{key}","extra":1}}}}"#
            ),
        ] {
            let parsed = serde_json::from_str::<DaemonConfig>(&bad);
            assert!(
                parsed.is_err()
                    || matches!(parsed.unwrap().validate(), Err(CoreError::InvalidConfig)),
                "{bad} must be rejected"
            );
        }
        let loopback: DaemonConfig = serde_json::from_str(&format!(
            r#"{{"hosted":{{"url":"ws://127.0.0.1:7448","pinned_server_public_key":"{key}"}}}}"#
        ))
        .expect("config");
        loopback.validate().expect("loopback is allowed for tests");
    }
}

#[cfg(test)]
mod retirement_tests {
    use super::*;
    #[test]
    fn retired_settings_fail_closed() {
        for field in [
            "relays",
            "dm_relays",
            "rooms",
            "geo_relays",
            "registry",
            "account_handle",
            "profile_publication",
            "relay_list_publication",
            "joined_geohashes",
        ] {
            let value = serde_json::json!({field: null});
            assert!(
                serde_json::from_value::<DaemonConfig>(value).is_err(),
                "{field}"
            );
        }
    }
}
