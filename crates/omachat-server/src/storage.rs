//! SQLite persistence for accounts, devices and handles.
//!
//! The hosted chat tables are gone. A database from that product (schema
//! version 1) is refused so this process cannot open it by mistake. The
//! storage key still seals a key-check record, so a copied database is useless
//! without the operator's key, but account metadata itself is not encrypted.

use chacha20poly1305::{
    Key, XChaCha20Poly1305, XNonce,
    aead::{Aead, KeyInit, Payload},
};
use rusqlite::{Connection, ErrorCode as SqliteCode, OptionalExtension, params};
use std::{error::Error, fmt, os::unix::fs::PermissionsExt, path::Path};
use zeroize::Zeroizing;

pub const SCHEMA_VERSION: u32 = 3;
const NONCE_BYTES: usize = 24;
const KEY_CHECK_PLAINTEXT: &[u8] = b"omachat-server storage key check";

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AccountRecord {
    pub id: String,
    pub handle: Option<String>,
    pub display_name: String,
    pub created_at: u64,
}

pub struct Storage {
    connection: Connection,
    key: Zeroizing<[u8; 32]>,
}

impl Storage {
    /// Open or create the database at `path`. A database created under a
    /// different storage key is refused rather than silently unreadable.
    pub fn open(path: &Path, key: Zeroizing<[u8; 32]>) -> Result<Self, StorageError> {
        let connection = Connection::open(path)?;
        // SQLite creates the database with the process umask and derives the
        // WAL and shared-memory files' modes from it, so tighten it before
        // the first write creates them.
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600)).map_err(
            |error| {
                StorageError::Sqlite(rusqlite::Error::SqliteFailure(
                    rusqlite::ffi::Error::new(rusqlite::ffi::SQLITE_CANTOPEN),
                    Some(format!("cannot restrict {}: {error}", path.display())),
                ))
            },
        )?;
        connection.execute_batch(
            "PRAGMA journal_mode = WAL;
             PRAGMA synchronous = FULL;
             PRAGMA foreign_keys = ON;
             PRAGMA busy_timeout = 5000;",
        )?;
        let mut storage = Self { connection, key };
        storage.migrate()?;
        storage.verify_key()?;
        Ok(storage)
    }

    /// In-memory database for tests.
    pub fn open_in_memory(key: Zeroizing<[u8; 32]>) -> Result<Self, StorageError> {
        let connection = Connection::open_in_memory()?;
        connection.execute_batch("PRAGMA foreign_keys = ON;")?;
        let mut storage = Self { connection, key };
        storage.migrate()?;
        storage.verify_key()?;
        Ok(storage)
    }

    fn migrate(&mut self) -> Result<(), StorageError> {
        self.connection.execute_batch(
            "CREATE TABLE IF NOT EXISTS meta (
                key TEXT PRIMARY KEY,
                value BLOB NOT NULL
            );
            CREATE TABLE IF NOT EXISTS accounts (
                id TEXT PRIMARY KEY,
                handle TEXT UNIQUE,
                display_name TEXT NOT NULL,
                created_at INTEGER NOT NULL
            );
            CREATE TABLE IF NOT EXISTS devices (
                public_key BLOB PRIMARY KEY,
                account_id TEXT NOT NULL REFERENCES accounts(id),
                created_at INTEGER NOT NULL,
                last_seen INTEGER NOT NULL
            );",
        )?;
        let version: Option<Vec<u8>> = self
            .connection
            .query_row(
                "SELECT value FROM meta WHERE key = 'schema_version'",
                [],
                |row| row.get(0),
            )
            .optional()?;
        match version.as_deref() {
            None | Some(b"2") => {
                self.connection.execute_batch(
                    "ALTER TABLE accounts ADD COLUMN nostr_pubkey BLOB;
                     CREATE UNIQUE INDEX IF NOT EXISTS accounts_nostr_pubkey
                        ON accounts(nostr_pubkey) WHERE nostr_pubkey IS NOT NULL;
                     CREATE TABLE IF NOT EXISTS nostr_proof_nonces (
                        nonce BLOB PRIMARY KEY,
                        account_id TEXT NOT NULL,
                        seen_at INTEGER NOT NULL
                     );",
                )?;
                self.connection.execute(
                    "INSERT INTO meta (key, value) VALUES ('schema_version', ?1)
                     ON CONFLICT(key) DO UPDATE SET value = excluded.value",
                    params![SCHEMA_VERSION.to_string().into_bytes()],
                )?;
            }
            Some(value) if value == SCHEMA_VERSION.to_string().as_bytes() => {}
            Some(b"1") => {
                return Err(StorageError::UnsupportedSchema(
                    "1 (hosted chat database; run that product from the hosted-archive branch)"
                        .to_owned(),
                ));
            }
            Some(value) => {
                return Err(StorageError::UnsupportedSchema(
                    String::from_utf8_lossy(value).into_owned(),
                ));
            }
        }
        Ok(())
    }

    fn verify_key(&mut self) -> Result<(), StorageError> {
        let stored: Option<Vec<u8>> = self
            .connection
            .query_row(
                "SELECT value FROM meta WHERE key = 'key_check'",
                [],
                |row| row.get(0),
            )
            .optional()?;
        match stored {
            None => {
                let sealed = seal_with(&self.key, b"key_check", KEY_CHECK_PLAINTEXT)?;
                self.connection.execute(
                    "INSERT INTO meta (key, value) VALUES ('key_check', ?1)",
                    params![sealed],
                )?;
                Ok(())
            }
            Some(sealed) => {
                let opened = self
                    .open_sealed(b"key_check", &sealed)
                    .map_err(|_| StorageError::WrongKey)?;
                if opened == KEY_CHECK_PLAINTEXT {
                    Ok(())
                } else {
                    Err(StorageError::WrongKey)
                }
            }
        }
    }

    fn open_sealed(&self, associated: &[u8], sealed: &[u8]) -> Result<Vec<u8>, StorageError> {
        if sealed.len() < NONCE_BYTES + 16 {
            return Err(StorageError::Corrupt);
        }
        let (nonce, ciphertext) = sealed.split_at(NONCE_BYTES);
        let nonce: [u8; NONCE_BYTES] = nonce.try_into().map_err(|_| StorageError::Corrupt)?;
        XChaCha20Poly1305::new(Key::from_slice(self.key.as_slice()))
            .decrypt(
                &XNonce::from(nonce),
                Payload {
                    msg: ciphertext,
                    aad: associated,
                },
            )
            .map_err(|_| StorageError::Corrupt)
    }

    // ----- accounts and devices -----

    pub fn account_for_device(
        &self,
        device_public_key: &[u8; 32],
    ) -> Result<Option<AccountRecord>, StorageError> {
        self.connection
            .query_row(
                "SELECT a.id, a.handle, a.display_name, a.created_at
                 FROM devices d JOIN accounts a ON a.id = d.account_id
                 WHERE d.public_key = ?1",
                params![device_public_key.as_slice()],
                account_row,
            )
            .optional()
            .map_err(StorageError::from)
    }

    pub fn account(&self, account_id: &str) -> Result<Option<AccountRecord>, StorageError> {
        self.connection
            .query_row(
                "SELECT id, handle, display_name, created_at FROM accounts WHERE id = ?1",
                params![account_id],
                account_row,
            )
            .optional()
            .map_err(StorageError::from)
    }

    pub fn touch_device(
        &mut self,
        device_public_key: &[u8; 32],
        now: u64,
    ) -> Result<(), StorageError> {
        self.connection.execute(
            "UPDATE devices SET last_seen = ?2 WHERE public_key = ?1",
            params![device_public_key.as_slice(), to_i64(now)],
        )?;
        Ok(())
    }

    pub fn create_account(
        &mut self,
        device_public_key: &[u8; 32],
        display_name: &str,
        now: u64,
    ) -> Result<AccountRecord, StorageError> {
        let id = random_id()?;
        let transaction = self.connection.transaction()?;
        transaction.execute(
            "INSERT INTO accounts (id, handle, display_name, created_at) VALUES (?1, NULL, ?2, ?3)",
            params![id, display_name, to_i64(now)],
        )?;
        transaction.execute(
            "INSERT INTO devices (public_key, account_id, created_at, last_seen) VALUES (?1, ?2, ?3, ?3)",
            params![device_public_key.as_slice(), id, to_i64(now)],
        )?;
        transaction.commit()?;
        Ok(AccountRecord {
            id,
            handle: None,
            display_name: display_name.to_owned(),
            created_at: now,
        })
    }

    pub fn claim_handle(&mut self, account_id: &str, handle: &str) -> Result<(), StorageError> {
        let existing: Option<Option<String>> = self
            .connection
            .query_row(
                "SELECT handle FROM accounts WHERE id = ?1",
                params![account_id],
                |row| row.get(0),
            )
            .optional()?;
        match existing {
            None => return Err(StorageError::NotFound),
            Some(Some(_)) => return Err(StorageError::HandleAlreadySet),
            Some(None) => {}
        }
        match self.connection.execute(
            "UPDATE accounts SET handle = ?2 WHERE id = ?1 AND handle IS NULL",
            params![account_id, handle],
        ) {
            Ok(_) => Ok(()),
            Err(error) if is_constraint(&error) => Err(StorageError::HandleTaken),
            Err(error) => Err(error.into()),
        }
    }

    pub fn resolve_handle(&self, handle: &str) -> Result<Option<AccountRecord>, StorageError> {
        self.connection
            .query_row(
                "SELECT id, handle, display_name, created_at FROM accounts WHERE handle = ?1",
                params![handle],
                account_row,
            )
            .optional()
            .map_err(StorageError::from)
    }

    pub fn nostr_pubkey(&self, account_id: &str) -> Result<Option<[u8; 32]>, StorageError> {
        let stored: Option<Option<Vec<u8>>> = self
            .connection
            .query_row(
                "SELECT nostr_pubkey FROM accounts WHERE id = ?1",
                params![account_id],
                |row| row.get(0),
            )
            .optional()?;
        match stored {
            None => Err(StorageError::NotFound),
            Some(None) => Ok(None),
            Some(Some(bytes)) => Ok(Some(fixed_key(&bytes)?)),
        }
    }

    /// Bind `pubkey` to this account, replacing a previous binding. Rejects a
    /// key that another account already holds.
    pub fn bind_nostr(&mut self, account_id: &str, pubkey: &[u8; 32]) -> Result<(), StorageError> {
        match self.connection.execute(
            "UPDATE accounts SET nostr_pubkey = ?2 WHERE id = ?1",
            params![account_id, pubkey.as_slice()],
        ) {
            Ok(0) => Err(StorageError::NotFound),
            Ok(_) => Ok(()),
            Err(error) if is_constraint(&error) => Err(StorageError::NostrPubkeyTaken),
            Err(error) => Err(error.into()),
        }
    }

    /// Returns whether a binding was removed.
    pub fn unbind_nostr(&mut self, account_id: &str) -> Result<bool, StorageError> {
        let changed = self.connection.execute(
            "UPDATE accounts SET nostr_pubkey = NULL WHERE id = ?1 AND nostr_pubkey IS NOT NULL",
            params![account_id],
        )?;
        if self.account(account_id)?.is_none() {
            return Err(StorageError::NotFound);
        }
        Ok(changed == 1)
    }

    pub fn nostr_for_handle(&self, handle: &str) -> Result<Option<[u8; 32]>, StorageError> {
        let stored: Option<Option<Vec<u8>>> = self
            .connection
            .query_row(
                "SELECT nostr_pubkey FROM accounts WHERE handle = ?1",
                params![handle],
                |row| row.get(0),
            )
            .optional()?;
        match stored {
            None | Some(None) => Ok(None),
            Some(Some(bytes)) => Ok(Some(fixed_key(&bytes)?)),
        }
    }

    /// Record a proof nonce. A repeat is a replay. Nonces older than the
    /// freshness window are dropped so the table stays bounded; a late replay
    /// is rejected by the timestamp check instead.
    pub fn remember_proof_nonce(
        &mut self,
        nonce: &[u8; 32],
        account_id: &str,
        now: u64,
        skew_seconds: u64,
    ) -> Result<(), StorageError> {
        let oldest = now.saturating_sub(skew_seconds);
        self.connection.execute(
            "DELETE FROM nostr_proof_nonces WHERE seen_at < ?1",
            params![to_i64(oldest)],
        )?;
        match self.connection.execute(
            "INSERT INTO nostr_proof_nonces (nonce, account_id, seen_at) VALUES (?1, ?2, ?3)",
            params![nonce.as_slice(), account_id, to_i64(now)],
        ) {
            Ok(_) => Ok(()),
            Err(error) if is_constraint(&error) => Err(StorageError::ReplayedProof),
            Err(error) => Err(error.into()),
        }
    }
}

fn account_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<AccountRecord> {
    Ok(AccountRecord {
        id: row.get(0)?,
        handle: row.get(1)?,
        display_name: row.get(2)?,
        created_at: from_i64(row.get(3)?),
    })
}

fn seal_with(key: &[u8; 32], associated: &[u8], plaintext: &[u8]) -> Result<Vec<u8>, StorageError> {
    let mut nonce = [0_u8; NONCE_BYTES];
    getrandom::fill(&mut nonce).map_err(|_| StorageError::Random)?;
    let ciphertext = XChaCha20Poly1305::new(Key::from_slice(key))
        .encrypt(
            &XNonce::from(nonce),
            Payload {
                msg: plaintext,
                aad: associated,
            },
        )
        .map_err(|_| StorageError::Seal)?;
    let mut output = Vec::with_capacity(NONCE_BYTES + ciphertext.len());
    output.extend_from_slice(&nonce);
    output.extend_from_slice(&ciphertext);
    Ok(output)
}

fn random_id() -> Result<String, StorageError> {
    let mut bytes = [0_u8; 16];
    getrandom::fill(&mut bytes).map_err(|_| StorageError::Random)?;
    Ok(hex::encode(bytes))
}

fn is_constraint(error: &rusqlite::Error) -> bool {
    matches!(
        error,
        rusqlite::Error::SqliteFailure(failure, _)
            if failure.code == SqliteCode::ConstraintViolation
    )
}

fn to_i64(value: u64) -> i64 {
    i64::try_from(value).unwrap_or(i64::MAX)
}

fn from_i64(value: i64) -> u64 {
    u64::try_from(value).unwrap_or(0)
}

fn fixed_key(bytes: &[u8]) -> Result<[u8; 32], StorageError> {
    bytes.try_into().map_err(|_| StorageError::Corrupt)
}

#[derive(Debug)]
pub enum StorageError {
    Sqlite(rusqlite::Error),
    UnsupportedSchema(String),
    WrongKey,
    Random,
    Seal,
    Corrupt,
    NotFound,
    HandleTaken,
    HandleAlreadySet,
    NostrPubkeyTaken,
    ReplayedProof,
}

impl From<rusqlite::Error> for StorageError {
    fn from(error: rusqlite::Error) -> Self {
        Self::Sqlite(error)
    }
}

impl fmt::Display for StorageError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Sqlite(error) => write!(formatter, "database failed: {error}"),
            Self::UnsupportedSchema(version) => {
                write!(
                    formatter,
                    "database schema version {version} is not supported"
                )
            }
            Self::WrongKey => formatter.write_str("the storage key does not open this database"),
            Self::Random => formatter.write_str("operating system randomness unavailable"),
            Self::Seal => formatter.write_str("sealing a message failed"),
            Self::Corrupt => formatter.write_str("a stored record failed authentication"),
            Self::NotFound => formatter.write_str("no such record"),
            Self::HandleTaken => formatter.write_str("handle already taken"),
            Self::HandleAlreadySet => formatter.write_str("account already has a handle"),
            Self::NostrPubkeyTaken => formatter.write_str("nostr public key is already bound"),
            Self::ReplayedProof => formatter.write_str("nostr proof nonce was already used"),
        }
    }
}

impl Error for StorageError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Sqlite(error) => Some(error),
            _ => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn storage() -> Storage {
        Storage::open_in_memory(Zeroizing::new([3_u8; 32])).unwrap()
    }

    #[test]
    fn accounts_devices_and_handles() {
        let mut storage = storage();
        let device = [1_u8; 32];
        assert!(storage.account_for_device(&device).unwrap().is_none());
        let account = storage.create_account(&device, "Ada", 10).unwrap();
        assert_eq!(
            storage.account_for_device(&device).unwrap().unwrap(),
            account
        );
        storage.claim_handle(&account.id, "ada").unwrap();
        assert!(matches!(
            storage.claim_handle(&account.id, "ada2"),
            Err(StorageError::HandleAlreadySet)
        ));
        let other = storage.create_account(&[2_u8; 32], "Bob", 11).unwrap();
        assert!(matches!(
            storage.claim_handle(&other.id, "ada"),
            Err(StorageError::HandleTaken)
        ));
        assert_eq!(
            storage.resolve_handle("ada").unwrap().unwrap().id,
            account.id
        );
    }

    #[test]
    fn wrong_storage_key_is_refused() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("server.db");
        drop(Storage::open(&path, Zeroizing::new([1_u8; 32])).unwrap());
        assert!(matches!(
            Storage::open(&path, Zeroizing::new([2_u8; 32])),
            Err(StorageError::WrongKey)
        ));
        drop(Storage::open(&path, Zeroizing::new([1_u8; 32])).unwrap());
    }
}
