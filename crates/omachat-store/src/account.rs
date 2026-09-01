use crate::{SealedStore, StoreError};
use omachat_crypto::{
    AccountError, AccountPublicIdentity, AccountSecrets, DevicePublicKeys, DisplayName,
    GlobalHandle, IdentityError, IdentitySecrets, SignedLocalAccountBinding,
};
use omachat_registry::{CommandId, HandleClaim, RegistryError};
use serde::{Deserialize, Serialize};
use std::{error::Error, fmt, io::Cursor};
use zeroize::Zeroizing;

const ACCOUNT_RECORD: &str = "account-v1";
const ACCOUNT_RECORD_VERSION: u16 = 1;
const MAX_ACCOUNT_RECORD_PLAINTEXT_BYTES: usize = 4 * 1024;
const INITIAL_BINDING_REVISION: u64 = 1;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct PersistedAccount {
    version: u16,
    secrets: AccountSecrets,
    binding: SignedLocalAccountBinding,
}

#[derive(Serialize)]
struct PersistedAccountRef<'account> {
    version: u16,
    secrets: &'account AccountSecrets,
    binding: &'account SignedLocalAccountBinding,
}

/// A sealed local account authority and its root-signed current device binding.
///
/// This type deliberately implements neither `Clone` nor `Debug`. Dropping it
/// drops and zeroizes the contained [`AccountSecrets`].
pub struct LocalAccount {
    secrets: AccountSecrets,
    binding: SignedLocalAccountBinding,
}

impl LocalAccount {
    #[must_use]
    pub fn public_identity(&self) -> AccountPublicIdentity {
        self.secrets.public_identity()
    }

    #[must_use]
    pub fn binding(&self) -> &SignedLocalAccountBinding {
        &self.binding
    }

    /// Sign one idempotent registry command for this account's current
    /// root-signed binding without exposing the account root as a general
    /// signing oracle.
    pub fn sign_registry_handle_claim(
        &self,
        command_id: CommandId,
        expected_revision: u64,
    ) -> Result<HandleClaim, RegistryError> {
        HandleClaim::sign(
            command_id,
            expected_revision,
            self.binding.clone(),
            &self.secrets,
        )
    }
}

/// Persistence boundary for the account authority and local profile binding.
pub struct AccountVault;

impl AccountVault {
    /// Load and validate the local account, creating it only when its sealed
    /// record is explicitly absent.
    ///
    /// `None` profile inputs mean "preserve the stored value" after first run.
    /// An explicitly supplied value replaces a different stored value and
    /// produces a newly signed, monotonically revisioned binding.
    pub fn load_or_create(
        store: &SealedStore,
        identity: &IdentitySecrets,
        configured_handle: Option<GlobalHandle>,
        configured_display_name: Option<DisplayName>,
        now: u64,
    ) -> Result<LocalAccount, AccountVaultError> {
        let device_keys = current_device_keys(identity)?;
        match store.read(ACCOUNT_RECORD) {
            Ok(bytes) => {
                // Take ownership of the decrypted allocation immediately so
                // every exit path wipes the serialized account/recovery seeds.
                let bytes = Zeroizing::new(bytes);
                let persisted: PersistedAccount =
                    serde_json::from_slice(&bytes).map_err(|_| AccountVaultError::Encoding)?;
                Self::validate_and_update(
                    store,
                    persisted,
                    device_keys,
                    configured_handle,
                    configured_display_name,
                    now,
                )
            }
            Err(StoreError::RecordNotFound) => {
                let secrets = AccountSecrets::generate().map_err(AccountVaultError::Account)?;
                let binding = secrets.sign_local_binding(
                    configured_handle,
                    configured_display_name,
                    device_keys,
                    INITIAL_BINDING_REVISION,
                    now,
                );
                let account = LocalAccount { secrets, binding };
                persist(store, &account)?;
                Ok(account)
            }
            Err(error) => Err(AccountVaultError::Store(error)),
        }
    }

    fn validate_and_update(
        store: &SealedStore,
        persisted: PersistedAccount,
        device_keys: DevicePublicKeys,
        configured_handle: Option<GlobalHandle>,
        configured_display_name: Option<DisplayName>,
        now: u64,
    ) -> Result<LocalAccount, AccountVaultError> {
        if persisted.version != ACCOUNT_RECORD_VERSION {
            return Err(AccountVaultError::UnsupportedVersion(persisted.version));
        }
        persisted
            .binding
            .verify()
            .map_err(AccountVaultError::Account)?;

        let public = persisted.secrets.public_identity();
        if persisted.binding.account_id != public.account_id
            || persisted.binding.account_root_public_key != public.account_root_public_key
            || persisted.binding.recovery_public_key != public.recovery_public_key
        {
            return Err(AccountVaultError::AccountAuthorityMismatch);
        }
        if persisted.binding.device_keys != device_keys {
            return Err(AccountVaultError::DeviceIdentityMismatch);
        }

        let handle = configured_handle.or_else(|| persisted.binding.handle.clone());
        let display_name =
            configured_display_name.or_else(|| persisted.binding.display_name.clone());
        let changed =
            handle != persisted.binding.handle || display_name != persisted.binding.display_name;
        let mut account = LocalAccount {
            secrets: persisted.secrets,
            binding: persisted.binding,
        };
        if changed {
            let revision = account
                .binding
                .revision
                .checked_add(1)
                .ok_or(AccountVaultError::RevisionOverflow)?;
            account.binding = account.secrets.sign_local_binding(
                handle,
                display_name,
                device_keys,
                revision,
                now.max(account.binding.issued_at),
            );
            persist(store, &account)?;
        }
        Ok(account)
    }
}

fn current_device_keys(identity: &IdentitySecrets) -> Result<DevicePublicKeys, AccountVaultError> {
    let public = identity.public_identity();
    let nostr = identity
        .device_nostr_identity()
        .map_err(AccountVaultError::Identity)?;
    Ok(DevicePublicKeys {
        signing_public_key: public.signing_public_key,
        noise_public_key: public.noise_public_key,
        nostr_public_key: *nostr.public_key(),
    })
}

fn persist(store: &SealedStore, account: &LocalAccount) -> Result<(), AccountVaultError> {
    // Serialize into a bounded zeroizing buffer. A growable Vec could leave
    // an earlier plaintext allocation behind when it reallocates.
    let mut encoded = Zeroizing::new([0_u8; MAX_ACCOUNT_RECORD_PLAINTEXT_BYTES]);
    let encoded_bytes = {
        let mut writer = Cursor::new(&mut encoded[..]);
        serde_json::to_writer(
            &mut writer,
            &PersistedAccountRef {
                version: ACCOUNT_RECORD_VERSION,
                secrets: &account.secrets,
                binding: &account.binding,
            },
        )
        .map_err(|_| AccountVaultError::Encoding)?;
        usize::try_from(writer.position()).map_err(|_| AccountVaultError::Encoding)?
    };
    store
        .write(ACCOUNT_RECORD, &encoded[..encoded_bytes])
        .map_err(AccountVaultError::Store)
}

#[derive(Debug)]
pub enum AccountVaultError {
    Store(StoreError),
    Account(AccountError),
    Identity(IdentityError),
    Encoding,
    UnsupportedVersion(u16),
    AccountAuthorityMismatch,
    DeviceIdentityMismatch,
    RevisionOverflow,
}

impl fmt::Display for AccountVaultError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Store(error) => write!(formatter, "account storage failed: {error}"),
            Self::Account(error) => write!(formatter, "account validation failed: {error}"),
            Self::Identity(error) => write!(formatter, "device identity failed: {error}"),
            Self::Encoding => formatter.write_str("account record encoding is invalid"),
            Self::UnsupportedVersion(version) => {
                write!(formatter, "unsupported account record version {version}")
            }
            Self::AccountAuthorityMismatch => {
                formatter.write_str("account secrets do not match the signed account authority")
            }
            Self::DeviceIdentityMismatch => {
                formatter.write_str("signed account device keys do not match the current identity")
            }
            Self::RevisionOverflow => formatter.write_str("account binding revision is exhausted"),
        }
    }
}

impl Error for AccountVaultError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Store(error) => Some(error),
            Self::Account(error) => Some(error),
            Self::Identity(error) => Some(error),
            _ => None,
        }
    }
}
