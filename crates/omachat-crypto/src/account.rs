use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use k256::schnorr::VerifyingKey as SchnorrVerifyingKey;
use serde::{Deserialize, Deserializer, Serialize, Serializer, de};
use sha2::{Digest, Sha256};
use std::{error::Error, fmt, str::FromStr};
use zeroize::{Zeroize, ZeroizeOnDrop};

const KEY_BYTES: usize = 32;
const SIGNATURE_BYTES: usize = 64;
const ID_HEX_BYTES: usize = KEY_BYTES * 2;
const ACCOUNT_ID_PREFIX: &str = "oa1_";
const DEVICE_ID_PREFIX: &str = "od1_";
const ACCOUNT_ID_DOMAIN: &[u8] = b"omachat.account.v1\0";
const DEVICE_ID_DOMAIN: &[u8] = b"omachat.device.v1\0";
const LOCAL_BINDING_DOMAIN: &[u8] = b"omachat.local-account-binding.v1\0";
const REGISTRY_HANDLE_CLAIM_PROOF_DOMAIN: &[u8] = b"omachat.registry-handle-claim-proof.v1\0";
const LOCAL_BINDING_VERSION: u16 = 1;
const MIN_HANDLE_BYTES: usize = 3;
const MAX_HANDLE_BYTES: usize = 32;
const MAX_DISPLAY_NAME_CHARS: usize = 80;
const MAX_DISPLAY_NAME_BYTES: usize = 256;

/// Cryptographically distinct account-level authority and recovery secrets.
///
/// These roots are deliberately separate from [`crate::IdentitySecrets`],
/// whose serialization and compatibility-critical device identities remain
/// unchanged. They are provisionally co-resident in one sealed local record;
/// this type alone is not an off-device recovery scheme.
#[derive(Deserialize, Serialize, Zeroize, ZeroizeOnDrop)]
#[serde(deny_unknown_fields)]
pub struct AccountSecrets {
    account_root_seed: [u8; KEY_BYTES],
    recovery_seed: [u8; KEY_BYTES],
}

impl AccountSecrets {
    pub fn generate() -> Result<Self, AccountError> {
        let mut account_root_seed = [0_u8; KEY_BYTES];
        let mut recovery_seed = [0_u8; KEY_BYTES];
        getrandom::fill(&mut account_root_seed).map_err(|_| AccountError::Random)?;
        let account_root_public_key = SigningKey::from_bytes(&account_root_seed)
            .verifying_key()
            .to_bytes();
        loop {
            getrandom::fill(&mut recovery_seed).map_err(|_| AccountError::Random)?;
            let recovery_public_key = SigningKey::from_bytes(&recovery_seed)
                .verifying_key()
                .to_bytes();
            if recovery_seed != account_root_seed && recovery_public_key != account_root_public_key
            {
                break;
            }
        }
        Ok(Self {
            account_root_seed,
            recovery_seed,
        })
    }

    #[must_use]
    pub fn from_seeds(account_root_seed: [u8; KEY_BYTES], recovery_seed: [u8; KEY_BYTES]) -> Self {
        Self {
            account_root_seed,
            recovery_seed,
        }
    }

    #[must_use]
    pub fn public_identity(&self) -> AccountPublicIdentity {
        let account_root_public_key = SigningKey::from_bytes(&self.account_root_seed)
            .verifying_key()
            .to_bytes();
        let recovery_public_key = SigningKey::from_bytes(&self.recovery_seed)
            .verifying_key()
            .to_bytes();
        AccountPublicIdentity {
            account_id: AccountId::derive(&account_root_public_key),
            account_root_public_key,
            recovery_public_key,
        }
    }

    /// Bind one local device and optional configured profile to this account.
    ///
    /// A binding remains available before handle registration. The signature
    /// covers every field using a deterministic length-delimited transcript;
    /// it never relies on a serializer's map ordering.
    #[must_use]
    pub fn sign_local_binding(
        &self,
        handle: Option<GlobalHandle>,
        display_name: Option<DisplayName>,
        device_keys: DevicePublicKeys,
        revision: u64,
        issued_at: u64,
    ) -> SignedLocalAccountBinding {
        let public = self.public_identity();
        let device_id = DeviceId::derive(&public.account_id, &device_keys.signing_public_key);
        let mut binding = SignedLocalAccountBinding {
            version: LOCAL_BINDING_VERSION,
            account_id: public.account_id,
            account_root_public_key: public.account_root_public_key,
            recovery_public_key: public.recovery_public_key,
            handle,
            display_name,
            device_id,
            device_keys,
            revision,
            issued_at,
            signature: [0_u8; SIGNATURE_BYTES],
        };
        binding.signature = SigningKey::from_bytes(&self.account_root_seed)
            .sign(&binding.signing_bytes())
            .to_bytes();
        binding
    }

    /// Authorize one already-hashed registry handle claim.
    ///
    /// The fixed-size digest keeps this authority narrow: callers cannot use
    /// it as a general-purpose account-root signing oracle. The signature is
    /// independently domain-separated from local account bindings.
    #[must_use]
    pub fn sign_registry_handle_claim(
        &self,
        claim_digest: &[u8; KEY_BYTES],
    ) -> [u8; SIGNATURE_BYTES] {
        SigningKey::from_bytes(&self.account_root_seed)
            .sign(&registry_handle_claim_proof_bytes(claim_digest))
            .to_bytes()
    }
}

/// Verify an account-root proof over one registry handle-claim digest.
pub fn verify_registry_handle_claim(
    account_root_public_key: &[u8; KEY_BYTES],
    claim_digest: &[u8; KEY_BYTES],
    signature: &[u8; SIGNATURE_BYTES],
) -> Result<(), AccountError> {
    VerifyingKey::from_bytes(account_root_public_key)
        .map_err(|_| AccountError::InvalidPublicKey)?
        .verify_strict(
            &registry_handle_claim_proof_bytes(claim_digest),
            &Signature::from_bytes(signature),
        )
        .map_err(|_| AccountError::InvalidSignature)
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AccountPublicIdentity {
    pub account_id: AccountId,
    pub account_root_public_key: [u8; KEY_BYTES],
    pub recovery_public_key: [u8; KEY_BYTES],
}

#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct AccountId(String);

impl AccountId {
    #[must_use]
    pub fn derive(account_root_public_key: &[u8; KEY_BYTES]) -> Self {
        Self(format!(
            "{ACCOUNT_ID_PREFIX}{}",
            domain_hash(ACCOUNT_ID_DOMAIN, &[account_root_public_key])
        ))
    }

    pub fn parse(value: &str) -> Result<Self, AccountError> {
        validate_prefixed_id(value, ACCOUNT_ID_PREFIX, AccountError::InvalidAccountId)?;
        Ok(Self(value.to_owned()))
    }

    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for AccountId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.0)
    }
}

impl FromStr for AccountId {
    type Err = AccountError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        Self::parse(value)
    }
}

impl Serialize for AccountId {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(self.as_str())
    }
}

impl<'de> Deserialize<'de> for AccountId {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = String::deserialize(deserializer)?;
        Self::parse(&value).map_err(de::Error::custom)
    }
}

#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct DeviceId(String);

impl DeviceId {
    #[must_use]
    pub fn derive(account_id: &AccountId, device_signing_public_key: &[u8; KEY_BYTES]) -> Self {
        Self(format!(
            "{DEVICE_ID_PREFIX}{}",
            domain_hash(
                DEVICE_ID_DOMAIN,
                &[account_id.as_str().as_bytes(), device_signing_public_key],
            )
        ))
    }

    pub fn parse(value: &str) -> Result<Self, AccountError> {
        validate_prefixed_id(value, DEVICE_ID_PREFIX, AccountError::InvalidDeviceId)?;
        Ok(Self(value.to_owned()))
    }

    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for DeviceId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.0)
    }
}

impl FromStr for DeviceId {
    type Err = AccountError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        Self::parse(value)
    }
}

impl Serialize for DeviceId {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(self.as_str())
    }
}

impl<'de> Deserialize<'de> for DeviceId {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = String::deserialize(deserializer)?;
        Self::parse(&value).map_err(de::Error::custom)
    }
}

/// A globally unique registry handle in canonical form, without the display
/// `@` prefix.
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct GlobalHandle(String);

impl GlobalHandle {
    pub fn parse(value: &str) -> Result<Self, AccountError> {
        let canonical = value.strip_prefix('@').unwrap_or(value);
        let bytes = canonical.as_bytes();
        if !(MIN_HANDLE_BYTES..=MAX_HANDLE_BYTES).contains(&bytes.len())
            || !bytes[0].is_ascii_lowercase()
            || !bytes[1..]
                .iter()
                .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || *byte == b'_')
        {
            return Err(AccountError::InvalidHandle);
        }
        Ok(Self(canonical.to_owned()))
    }

    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for GlobalHandle {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.0)
    }
}

impl FromStr for GlobalHandle {
    type Err = AccountError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        Self::parse(value)
    }
}

impl Serialize for GlobalHandle {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(self.as_str())
    }
}

impl<'de> Deserialize<'de> for GlobalHandle {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = String::deserialize(deserializer)?;
        Self::parse(&value).map_err(de::Error::custom)
    }
}

/// A human-facing account name with explicit character and UTF-8 bounds.
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct DisplayName(String);

impl DisplayName {
    pub fn parse(value: &str) -> Result<Self, AccountError> {
        let characters = value.chars().count();
        if characters == 0
            || characters > MAX_DISPLAY_NAME_CHARS
            || value.len() > MAX_DISPLAY_NAME_BYTES
            || value.trim() != value
            || value
                .chars()
                .any(|character| character.is_control() || is_unsafe_display_format(character))
        {
            return Err(AccountError::InvalidDisplayName);
        }
        Ok(Self(value.to_owned()))
    }

    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for DisplayName {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.0)
    }
}

impl FromStr for DisplayName {
    type Err = AccountError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        Self::parse(value)
    }
}

impl Serialize for DisplayName {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(self.as_str())
    }
}

impl<'de> Deserialize<'de> for DisplayName {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = String::deserialize(deserializer)?;
        Self::parse(&value).map_err(de::Error::custom)
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct DevicePublicKeys {
    pub signing_public_key: [u8; KEY_BYTES],
    pub noise_public_key: [u8; KEY_BYTES],
    pub nostr_public_key: [u8; KEY_BYTES],
}

/// Root-signed local account/profile binding for one device.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SignedLocalAccountBinding {
    pub version: u16,
    pub account_id: AccountId,
    pub account_root_public_key: [u8; KEY_BYTES],
    pub recovery_public_key: [u8; KEY_BYTES],
    pub handle: Option<GlobalHandle>,
    pub display_name: Option<DisplayName>,
    pub device_id: DeviceId,
    pub device_keys: DevicePublicKeys,
    pub revision: u64,
    pub issued_at: u64,
    #[serde(with = "signature_hex")]
    pub signature: [u8; SIGNATURE_BYTES],
}

impl SignedLocalAccountBinding {
    /// Deterministic domain-separated transcript covered by the account root.
    #[must_use]
    pub fn signing_bytes(&self) -> Vec<u8> {
        let mut output = Vec::with_capacity(512);
        output.extend_from_slice(LOCAL_BINDING_DOMAIN);
        output.extend_from_slice(&self.version.to_be_bytes());
        push_bytes(&mut output, self.account_id.as_str().as_bytes());
        output.extend_from_slice(&self.account_root_public_key);
        output.extend_from_slice(&self.recovery_public_key);
        push_optional_string(&mut output, self.handle.as_ref().map(GlobalHandle::as_str));
        push_optional_string(
            &mut output,
            self.display_name.as_ref().map(DisplayName::as_str),
        );
        push_bytes(&mut output, self.device_id.as_str().as_bytes());
        output.extend_from_slice(&self.device_keys.signing_public_key);
        output.extend_from_slice(&self.device_keys.noise_public_key);
        output.extend_from_slice(&self.device_keys.nostr_public_key);
        output.extend_from_slice(&self.revision.to_be_bytes());
        output.extend_from_slice(&self.issued_at.to_be_bytes());
        output
    }

    pub fn verify(&self) -> Result<(), AccountError> {
        if self.version != LOCAL_BINDING_VERSION {
            return Err(AccountError::UnsupportedBindingVersion(self.version));
        }
        if self.revision == 0 {
            return Err(AccountError::InvalidBindingRevision);
        }
        if self.account_id != AccountId::derive(&self.account_root_public_key) {
            return Err(AccountError::AccountIdMismatch);
        }
        if self.recovery_public_key == self.account_root_public_key {
            return Err(AccountError::RecoveryAuthorityReuse);
        }
        if self.device_id
            != DeviceId::derive(&self.account_id, &self.device_keys.signing_public_key)
        {
            return Err(AccountError::DeviceIdMismatch);
        }
        VerifyingKey::from_bytes(&self.recovery_public_key)
            .map_err(|_| AccountError::InvalidPublicKey)?;
        VerifyingKey::from_bytes(&self.device_keys.signing_public_key)
            .map_err(|_| AccountError::InvalidPublicKey)?;
        if self.device_keys.noise_public_key == [0_u8; KEY_BYTES] {
            return Err(AccountError::InvalidPublicKey);
        }
        SchnorrVerifyingKey::from_bytes(&self.device_keys.nostr_public_key)
            .map_err(|_| AccountError::InvalidPublicKey)?;
        VerifyingKey::from_bytes(&self.account_root_public_key)
            .map_err(|_| AccountError::InvalidPublicKey)?
            .verify_strict(
                &self.signing_bytes(),
                &Signature::from_bytes(&self.signature),
            )
            .map_err(|_| AccountError::InvalidSignature)
    }
}

impl AccountSecrets {
    pub(crate) fn sign_account_root_transcript(&self, transcript: &[u8]) -> [u8; 64] {
        SigningKey::from_bytes(&self.account_root_seed)
            .sign(transcript)
            .to_bytes()
    }
}

fn domain_hash(domain: &[u8], components: &[&[u8]]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(domain);
    for component in components {
        hasher.update(component);
    }
    hex::encode(hasher.finalize())
}

fn validate_prefixed_id(
    value: &str,
    prefix: &str,
    error: AccountError,
) -> Result<(), AccountError> {
    let Some(digest) = value.strip_prefix(prefix) else {
        return Err(error);
    };
    if digest.len() != ID_HEX_BYTES
        || !digest
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(error);
    }
    Ok(())
}

fn is_unsafe_display_format(character: char) -> bool {
    matches!(
        character,
        '\u{00ad}'
            | '\u{061c}'
            | '\u{200b}'..='\u{200f}'
            | '\u{202a}'..='\u{202e}'
            | '\u{2060}'..='\u{206f}'
            | '\u{feff}'
            | '\u{fff9}'..='\u{fffb}'
            | '\u{e0000}'..='\u{e007f}'
    )
}

fn push_bytes(output: &mut Vec<u8>, value: &[u8]) {
    let length = u32::try_from(value.len()).expect("bounded account field length fits u32");
    output.extend_from_slice(&length.to_be_bytes());
    output.extend_from_slice(value);
}

fn push_optional_string(output: &mut Vec<u8>, value: Option<&str>) {
    match value {
        Some(value) => {
            output.push(1);
            push_bytes(output, value.as_bytes());
        }
        None => output.push(0),
    }
}

fn registry_handle_claim_proof_bytes(claim_digest: &[u8; KEY_BYTES]) -> Vec<u8> {
    let mut output = Vec::with_capacity(REGISTRY_HANDLE_CLAIM_PROOF_DOMAIN.len() + KEY_BYTES);
    output.extend_from_slice(REGISTRY_HANDLE_CLAIM_PROOF_DOMAIN);
    output.extend_from_slice(claim_digest);
    output
}

mod signature_hex {
    use super::{SIGNATURE_BYTES, de};
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S>(signature: &[u8; SIGNATURE_BYTES], serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&hex::encode(signature))
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<[u8; SIGNATURE_BYTES], D::Error>
    where
        D: Deserializer<'de>,
    {
        let encoded = String::deserialize(deserializer)?;
        if encoded.len() != SIGNATURE_BYTES * 2
            || !encoded
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        {
            return Err(de::Error::custom("invalid lowercase Ed25519 signature"));
        }
        hex::decode(encoded)
            .map_err(de::Error::custom)?
            .try_into()
            .map_err(|_| de::Error::custom("invalid Ed25519 signature length"))
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AccountError {
    Random,
    InvalidAccountId,
    InvalidDeviceId,
    InvalidHandle,
    InvalidDisplayName,
    UnsupportedBindingVersion(u16),
    InvalidBindingRevision,
    AccountIdMismatch,
    RecoveryAuthorityReuse,
    DeviceIdMismatch,
    InvalidPublicKey,
    InvalidSignature,
}

impl fmt::Display for AccountError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Random => formatter.write_str("secure account random generation failed"),
            Self::InvalidAccountId => formatter.write_str("invalid OmaChat account ID"),
            Self::InvalidDeviceId => formatter.write_str("invalid OmaChat device ID"),
            Self::InvalidHandle => formatter.write_str("invalid global OmaChat handle"),
            Self::InvalidDisplayName => formatter.write_str("invalid OmaChat display name"),
            Self::UnsupportedBindingVersion(version) => {
                write!(
                    formatter,
                    "unsupported local account binding version {version}"
                )
            }
            Self::InvalidBindingRevision => {
                formatter.write_str("local account binding revision must be positive")
            }
            Self::AccountIdMismatch => {
                formatter.write_str("account ID does not match the account root")
            }
            Self::RecoveryAuthorityReuse => {
                formatter.write_str("account and recovery authorities must be distinct")
            }
            Self::DeviceIdMismatch => {
                formatter.write_str("device ID does not match the device signing key")
            }
            Self::InvalidPublicKey => formatter.write_str("invalid account device public key"),
            Self::InvalidSignature => {
                formatter.write_str("invalid local account binding signature")
            }
        }
    }
}

impl Error for AccountError {}
