use chacha20poly1305::{
    Key, XChaCha20Poly1305, XNonce,
    aead::{Aead, KeyInit, Payload},
};
use secret_service::{EncryptionType, SecretService};
use serde::{Deserialize, Serialize};
use std::{
    collections::HashMap,
    error::Error,
    fmt,
    fs::{self, File, OpenOptions},
    io::{Read, Write},
    os::unix::fs::{OpenOptionsExt, PermissionsExt},
    path::{Path, PathBuf},
    sync::Mutex,
};
use zeroize::{Zeroize, Zeroizing};

const MODE_MARKER: &str = "storage-mode";
pub(crate) const FILE_KEY_NAME: &str = "master.key";
const RECORD_DIRECTORY: &str = "records";
const RECORD_MAGIC: &[u8; 8] = b"OMACREC\0";
const RECORD_VERSION: u8 = 1;
const NONCE_BYTES: usize = 24;
const TAG_BYTES: usize = 16;
const KEY_BYTES: usize = 32;
pub(crate) const MAX_RECORD_BYTES: usize = 4 * 1024 * 1024;
const SECRET_APPLICATION: &str = "omachat";
const SECRET_PURPOSE: &str = "master-key-v1";

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum ProviderKind {
    SecretService,
    File,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RequestedProvider {
    Auto,
    SecretService,
    File,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
pub struct StoreStatus {
    pub provider: ProviderKind,
    pub record_version: u8,
}

/// Zeroized 256-bit master key. It deliberately has no `Clone` or debug view.
pub struct MasterKey(Zeroizing<[u8; KEY_BYTES]>);

impl MasterKey {
    pub fn from_bytes(bytes: [u8; KEY_BYTES]) -> Self {
        Self(Zeroizing::new(bytes))
    }

    fn generate() -> Result<Self, StoreError> {
        let mut bytes = [0_u8; KEY_BYTES];
        getrandom::fill(&mut bytes).map_err(|_| StoreError::Random)?;
        Ok(Self::from_bytes(bytes))
    }

    fn expose(&self) -> &[u8; KEY_BYTES] {
        &self.0
    }

    pub(crate) fn zeroize(&mut self) {
        self.0.zeroize();
    }
}

pub struct SealedStore {
    pub(crate) state_directory: PathBuf,
    pub(crate) records_directory: PathBuf,
    pub(crate) provider: ProviderKind,
    pub(crate) key: Mutex<MasterKey>,
}

impl SealedStore {
    /// Open an existing store or make its one-time first-run provider choice.
    /// An existing unavailable provider always fails closed.
    pub async fn open(
        state_directory: impl AsRef<Path>,
        requested: RequestedProvider,
    ) -> Result<Self, StoreError> {
        let state_directory = state_directory.as_ref().to_owned();
        ensure_private_directory(&state_directory)?;
        let marker = state_directory.join(MODE_MARKER);
        let existing = read_provider(&marker)?;

        let (provider, key) = match existing {
            Some(provider) => {
                if !request_matches(requested, provider) {
                    return Err(StoreError::ProviderConflict);
                }
                let key = match provider {
                    ProviderKind::SecretService => load_secret_service_key(false).await?,
                    ProviderKind::File => load_file_key(&state_directory)?,
                };
                (provider, key)
            }
            None => select_first_run(&state_directory, requested).await?,
        };

        if existing.is_none() {
            atomic_write(&marker, provider_name(provider).as_bytes())?;
        }
        let records_directory = state_directory.join(RECORD_DIRECTORY);
        ensure_private_directory(&records_directory)?;
        recover_interrupted_writes(&records_directory)?;
        Ok(Self {
            state_directory,
            records_directory,
            provider,
            key: Mutex::new(key),
        })
    }

    /// Explicitly migrate every sealed record to a different provider. The
    /// replacement tree is fully written before a same-filesystem directory
    /// swap; the provider marker changes only with that completed tree.
    pub async fn migrate_provider(
        state_directory: impl AsRef<Path>,
        target: ProviderKind,
    ) -> Result<(), StoreError> {
        let state_directory = state_directory.as_ref().to_owned();
        let source = Self::open(&state_directory, RequestedProvider::Auto).await?;
        let source_provider = source.provider;
        if source_provider == target {
            return Err(StoreError::ProviderConflict);
        }
        let mut records = Vec::new();
        for entry in fs::read_dir(&source.records_directory).map_err(StoreError::Io)? {
            let entry = entry.map_err(StoreError::Io)?;
            if !entry.file_type().map_err(StoreError::Io)?.is_file() {
                continue;
            }
            let name = entry
                .file_name()
                .into_string()
                .map_err(|_| StoreError::InvalidRecordName)?;
            records.push((name.clone(), Zeroizing::new(source.read(&name)?)));
        }
        let parent = state_directory
            .parent()
            .ok_or(StoreError::UnsafeEraseTarget)?;
        let leaf = state_directory
            .file_name()
            .and_then(|name| name.to_str())
            .ok_or(StoreError::UnsafeEraseTarget)?;
        let mut random = [0_u8; 8];
        getrandom::fill(&mut random).map_err(|_| StoreError::Random)?;
        let suffix = u64::from_le_bytes(random);
        let replacement_path = parent.join(format!(".{leaf}.migration-{suffix}"));
        let backup_path = parent.join(format!(".{leaf}.backup-{suffix}"));
        let requested = match target {
            ProviderKind::SecretService => RequestedProvider::SecretService,
            ProviderKind::File => RequestedProvider::File,
        };
        let replacement = match Self::open(&replacement_path, requested).await {
            Ok(store) => store,
            Err(error) => {
                let _ = fs::remove_dir_all(&replacement_path);
                return Err(error);
            }
        };
        for (name, plaintext) in &records {
            if let Err(error) = replacement.write(name, plaintext) {
                drop(replacement);
                let _ = fs::remove_dir_all(&replacement_path);
                if target == ProviderKind::SecretService {
                    let _ = delete_secret_service_key().await;
                }
                return Err(error);
            }
        }
        drop(replacement);
        drop(source);
        fs::rename(&state_directory, &backup_path).map_err(StoreError::Io)?;
        if let Err(error) = fs::rename(&replacement_path, &state_directory) {
            let _ = fs::rename(&backup_path, &state_directory);
            if target == ProviderKind::SecretService {
                let _ = delete_secret_service_key().await;
            }
            return Err(StoreError::Io(error));
        }
        sync_directory(parent)?;
        if source_provider == ProviderKind::SecretService {
            delete_secret_service_key().await?;
        }
        fs::remove_dir_all(&backup_path).map_err(StoreError::Io)?;
        sync_directory(parent)
    }

    #[must_use]
    pub fn status(&self) -> StoreStatus {
        StoreStatus {
            provider: self.provider,
            record_version: RECORD_VERSION,
        }
    }

    #[must_use]
    pub fn state_directory(&self) -> &Path {
        &self.state_directory
    }

    /// Seal and atomically replace one named record. The name is authenticated
    /// as associated data to prevent ciphertext swaps between logical records.
    pub fn write(&self, name: &str, plaintext: &[u8]) -> Result<(), StoreError> {
        validate_record_name(name)?;
        if plaintext.len() > MAX_RECORD_BYTES {
            return Err(StoreError::RecordTooLarge);
        }
        let mut nonce = [0_u8; NONCE_BYTES];
        getrandom::fill(&mut nonce).map_err(|_| StoreError::Random)?;
        self.write_with_nonce(name, plaintext, &nonce)
    }

    pub fn read(&self, name: &str) -> Result<Vec<u8>, StoreError> {
        validate_record_name(name)?;
        let path = self.records_directory.join(name);
        let mut bytes = Vec::new();
        OpenOptions::new()
            .read(true)
            .open(path)
            .map_err(|error| {
                if error.kind() == std::io::ErrorKind::NotFound {
                    StoreError::RecordNotFound
                } else {
                    StoreError::Io(error)
                }
            })?
            .take((MAX_RECORD_BYTES + NONCE_BYTES + TAG_BYTES + 10) as u64)
            .read_to_end(&mut bytes)
            .map_err(StoreError::Io)?;
        if bytes.len() > MAX_RECORD_BYTES + NONCE_BYTES + TAG_BYTES + 9 {
            return Err(StoreError::RecordTooLarge);
        }
        if bytes.len() < RECORD_MAGIC.len() + 1 + NONCE_BYTES + TAG_BYTES
            || &bytes[..RECORD_MAGIC.len()] != RECORD_MAGIC
        {
            return Err(StoreError::InvalidEnvelope);
        }
        if bytes[RECORD_MAGIC.len()] != RECORD_VERSION {
            return Err(StoreError::UnsupportedVersion(bytes[RECORD_MAGIC.len()]));
        }
        let nonce_start = RECORD_MAGIC.len() + 1;
        let ciphertext_start = nonce_start + NONCE_BYTES;
        let nonce = XNonce::from(
            <[u8; NONCE_BYTES]>::try_from(&bytes[nonce_start..ciphertext_start])
                .expect("validated fixed nonce slice"),
        );
        XChaCha20Poly1305::new(&Key::from(
            *self.key.lock().expect("master-key mutex poisoned").expose(),
        ))
        .decrypt(
            &nonce,
            Payload {
                msg: &bytes[ciphertext_start..],
                aad: record_aad(name).as_slice(),
            },
        )
        .map_err(|_| StoreError::Authentication)
    }

    pub fn delete(&self, name: &str) -> Result<(), StoreError> {
        validate_record_name(name)?;
        match fs::remove_file(self.records_directory.join(name)) {
            Ok(()) => sync_directory(&self.records_directory),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(error) => Err(StoreError::Io(error)),
        }
    }

    fn write_with_nonce(
        &self,
        name: &str,
        plaintext: &[u8],
        nonce: &[u8; NONCE_BYTES],
    ) -> Result<(), StoreError> {
        let ciphertext = XChaCha20Poly1305::new(&Key::from(
            *self.key.lock().expect("master-key mutex poisoned").expose(),
        ))
        .encrypt(
            &XNonce::from(*nonce),
            Payload {
                msg: plaintext,
                aad: record_aad(name).as_slice(),
            },
        )
        .map_err(|_| StoreError::Encryption)?;
        let mut envelope =
            Vec::with_capacity(RECORD_MAGIC.len() + 1 + NONCE_BYTES + ciphertext.len());
        envelope.extend_from_slice(RECORD_MAGIC);
        envelope.push(RECORD_VERSION);
        envelope.extend_from_slice(nonce);
        envelope.extend_from_slice(&ciphertext);
        atomic_write(&self.records_directory.join(name), &envelope)
    }
}

async fn select_first_run(
    state_directory: &Path,
    requested: RequestedProvider,
) -> Result<(ProviderKind, MasterKey), StoreError> {
    match requested {
        RequestedProvider::SecretService => Ok((
            ProviderKind::SecretService,
            load_secret_service_key(true).await?,
        )),
        RequestedProvider::File => Ok((ProviderKind::File, create_file_key(state_directory)?)),
        RequestedProvider::Auto => match load_secret_service_key(true).await {
            Ok(key) => Ok((ProviderKind::SecretService, key)),
            Err(StoreError::SecretServiceUnavailable | StoreError::SecretServiceLocked) => {
                Ok((ProviderKind::File, create_file_key(state_directory)?))
            }
            Err(error) => Err(error),
        },
    }
}

async fn load_secret_service_key(create: bool) -> Result<MasterKey, StoreError> {
    let service = SecretService::connect(EncryptionType::Dh)
        .await
        .map_err(|_| StoreError::SecretServiceUnavailable)?;
    let collection = service
        .get_default_collection()
        .await
        .map_err(|_| StoreError::SecretServiceUnavailable)?;
    if collection
        .is_locked()
        .await
        .map_err(|_| StoreError::SecretServiceUnavailable)?
    {
        return Err(StoreError::SecretServiceLocked);
    }
    let attributes = HashMap::from([
        ("application", SECRET_APPLICATION),
        ("purpose", SECRET_PURPOSE),
    ]);
    let items = collection
        .search_items(attributes.clone())
        .await
        .map_err(|_| StoreError::SecretServiceUnavailable)?;
    if items.len() > 1 {
        return Err(StoreError::DuplicateMasterKey);
    }
    if let Some(item) = items.first() {
        let secret = item
            .get_secret()
            .await
            .map_err(|_| StoreError::SecretServiceUnavailable)?;
        return decode_key(&secret);
    }
    if !create {
        return Err(StoreError::MissingMasterKey);
    }
    let key = MasterKey::generate()?;
    collection
        .create_item(
            "OmaChat master key",
            attributes,
            key.expose(),
            false,
            "application/octet-stream",
        )
        .await
        .map_err(|_| StoreError::SecretServiceUnavailable)?;
    Ok(key)
}

pub(crate) async fn delete_secret_service_key() -> Result<(), StoreError> {
    let service = SecretService::connect(EncryptionType::Dh)
        .await
        .map_err(|_| StoreError::SecretServiceUnavailable)?;
    let collection = service
        .get_default_collection()
        .await
        .map_err(|_| StoreError::SecretServiceUnavailable)?;
    if collection
        .is_locked()
        .await
        .map_err(|_| StoreError::SecretServiceUnavailable)?
    {
        return Err(StoreError::SecretServiceLocked);
    }
    let items = collection
        .search_items(HashMap::from([
            ("application", SECRET_APPLICATION),
            ("purpose", SECRET_PURPOSE),
        ]))
        .await
        .map_err(|_| StoreError::SecretServiceUnavailable)?;
    if items.len() != 1 {
        return Err(if items.is_empty() {
            StoreError::MissingMasterKey
        } else {
            StoreError::DuplicateMasterKey
        });
    }
    items[0]
        .delete()
        .await
        .map_err(|_| StoreError::SecretServiceUnavailable)
}

fn create_file_key(state_directory: &Path) -> Result<MasterKey, StoreError> {
    let path = state_directory.join(FILE_KEY_NAME);
    if path.exists() {
        return Err(StoreError::ProviderStateExists);
    }
    let key = MasterKey::generate()?;
    atomic_write(&path, key.expose())?;
    Ok(key)
}

fn load_file_key(state_directory: &Path) -> Result<MasterKey, StoreError> {
    let path = state_directory.join(FILE_KEY_NAME);
    let metadata = fs::metadata(&path).map_err(|error| {
        if error.kind() == std::io::ErrorKind::NotFound {
            StoreError::MissingMasterKey
        } else {
            StoreError::Io(error)
        }
    })?;
    if metadata.permissions().mode() & 0o077 != 0 {
        return Err(StoreError::InsecurePermissions);
    }
    decode_key(&fs::read(path).map_err(StoreError::Io)?)
}

fn decode_key(bytes: &[u8]) -> Result<MasterKey, StoreError> {
    let key = <[u8; KEY_BYTES]>::try_from(bytes).map_err(|_| StoreError::InvalidMasterKey)?;
    Ok(MasterKey::from_bytes(key))
}

fn request_matches(requested: RequestedProvider, selected: ProviderKind) -> bool {
    matches!(requested, RequestedProvider::Auto)
        || matches!(
            (requested, selected),
            (
                RequestedProvider::SecretService,
                ProviderKind::SecretService
            ) | (RequestedProvider::File, ProviderKind::File)
        )
}

fn provider_name(provider: ProviderKind) -> &'static str {
    match provider {
        ProviderKind::SecretService => "secret-service\n",
        ProviderKind::File => "file\n",
    }
}

fn read_provider(path: &Path) -> Result<Option<ProviderKind>, StoreError> {
    let value = match fs::read_to_string(path) {
        Ok(value) => value,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(StoreError::Io(error)),
    };
    match value.trim() {
        "secret-service" => Ok(Some(ProviderKind::SecretService)),
        "file" => Ok(Some(ProviderKind::File)),
        _ => Err(StoreError::InvalidProviderMarker),
    }
}

fn ensure_private_directory(path: &Path) -> Result<(), StoreError> {
    fs::create_dir_all(path).map_err(StoreError::Io)?;
    fs::set_permissions(path, fs::Permissions::from_mode(0o700)).map_err(StoreError::Io)
}

fn atomic_write(path: &Path, bytes: &[u8]) -> Result<(), StoreError> {
    let parent = path.parent().ok_or(StoreError::InvalidPath)?;
    let file_name = path
        .file_name()
        .and_then(|name| name.to_str())
        .ok_or(StoreError::InvalidPath)?;
    let mut random = [0_u8; 8];
    getrandom::fill(&mut random).map_err(|_| StoreError::Random)?;
    let temporary = parent.join(format!(
        ".{file_name}.tmp-{}-{}",
        std::process::id(),
        u64::from_le_bytes(random)
    ));
    let result = (|| {
        let mut file = OpenOptions::new()
            .create_new(true)
            .write(true)
            .mode(0o600)
            .open(&temporary)
            .map_err(StoreError::Io)?;
        file.write_all(bytes).map_err(StoreError::Io)?;
        file.sync_all().map_err(StoreError::Io)?;
        drop(file);
        fs::rename(&temporary, path).map_err(StoreError::Io)?;
        fs::set_permissions(path, fs::Permissions::from_mode(0o600)).map_err(StoreError::Io)?;
        sync_directory(parent)
    })();
    if result.is_err() {
        let _ = fs::remove_file(&temporary);
    }
    result
}

pub(crate) fn sync_directory(path: &Path) -> Result<(), StoreError> {
    File::open(path)
        .and_then(|directory| directory.sync_all())
        .map_err(StoreError::Io)
}

fn recover_interrupted_writes(directory: &Path) -> Result<(), StoreError> {
    for entry in fs::read_dir(directory).map_err(StoreError::Io)? {
        let entry = entry.map_err(StoreError::Io)?;
        let name = entry.file_name();
        let Some(name) = name.to_str() else {
            continue;
        };
        if name.starts_with('.') && name.contains(".tmp-") {
            fs::remove_file(entry.path()).map_err(StoreError::Io)?;
        }
    }
    sync_directory(directory)
}

fn validate_record_name(name: &str) -> Result<(), StoreError> {
    if name.is_empty()
        || name.len() > 128
        || name.starts_with('.')
        || !name
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
    {
        Err(StoreError::InvalidRecordName)
    } else {
        Ok(())
    }
}

fn record_aad(name: &str) -> Vec<u8> {
    let mut aad = Vec::with_capacity(RECORD_MAGIC.len() + 1 + name.len());
    aad.extend_from_slice(RECORD_MAGIC);
    aad.push(RECORD_VERSION);
    aad.extend_from_slice(name.as_bytes());
    aad
}

#[derive(Debug)]
pub enum StoreError {
    Io(std::io::Error),
    Random,
    SecretServiceUnavailable,
    SecretServiceLocked,
    MissingMasterKey,
    DuplicateMasterKey,
    InvalidMasterKey,
    InvalidProviderMarker,
    ProviderConflict,
    ProviderStateExists,
    InsecurePermissions,
    InvalidRecordName,
    InvalidPath,
    InvalidEnvelope,
    RecordNotFound,
    UnsupportedVersion(u8),
    RecordTooLarge,
    Encryption,
    Authentication,
    UnsafeEraseTarget,
}

impl fmt::Display for StoreError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io(error) => write!(formatter, "storage I/O failed: {error}"),
            Self::Random => formatter.write_str("secure random generation failed"),
            Self::SecretServiceUnavailable => formatter.write_str("Secret Service is unavailable"),
            Self::SecretServiceLocked => formatter.write_str("Secret Service collection is locked"),
            Self::MissingMasterKey => formatter.write_str("selected provider has no master key"),
            Self::DuplicateMasterKey => {
                formatter.write_str("Secret Service contains duplicate OmaChat master keys")
            }
            Self::InvalidMasterKey => formatter.write_str("master key has an invalid length"),
            Self::InvalidProviderMarker => {
                formatter.write_str("storage provider marker is invalid")
            }
            Self::ProviderConflict => {
                formatter.write_str("requested provider conflicts with the sticky provider choice")
            }
            Self::ProviderStateExists => {
                formatter.write_str("unselected provider state already exists")
            }
            Self::InsecurePermissions => {
                formatter.write_str("file master key permissions are broader than 0600")
            }
            Self::InvalidRecordName => formatter.write_str("invalid sealed record name"),
            Self::InvalidPath => formatter.write_str("invalid storage path"),
            Self::InvalidEnvelope => formatter.write_str("sealed record envelope is invalid"),
            Self::RecordNotFound => formatter.write_str("sealed record does not exist"),
            Self::UnsupportedVersion(version) => {
                write!(formatter, "unsupported sealed record version {version}")
            }
            Self::RecordTooLarge => formatter.write_str("sealed record exceeds the resource limit"),
            Self::Encryption => formatter.write_str("record encryption failed"),
            Self::Authentication => formatter.write_str("record authentication failed"),
            Self::UnsafeEraseTarget => formatter.write_str("refusing unsafe panic-erase target"),
        }
    }
}

impl Error for StoreError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Io(error) => Some(error),
            _ => None,
        }
    }
}
