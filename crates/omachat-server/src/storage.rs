//! SQLite-backed persistence with message bodies encrypted at rest.
//!
//! Metadata (accounts, membership, sequences, receipts) is stored in the
//! clear so the server can enforce authorization and ordering. Message text
//! is sealed with XChaCha20-Poly1305 under the operator's storage key, with
//! the conversation, sequence and message identifier as associated data, so a
//! copied database file exposes structure but not content and rows cannot be
//! moved between conversations.

use chacha20poly1305::{
    Key, XChaCha20Poly1305, XNonce,
    aead::{Aead, KeyInit, Payload},
};
use rusqlite::{Connection, ErrorCode as SqliteCode, OptionalExtension, params};
use std::{error::Error, fmt, os::unix::fs::PermissionsExt, path::Path};
use zeroize::Zeroizing;

pub const SCHEMA_VERSION: u32 = 1;
const NONCE_BYTES: usize = 24;
const KEY_CHECK_PLAINTEXT: &[u8] = b"omachat-server storage key check";

pub const KIND_CHANNEL: &str = "channel";
pub const KIND_DM: &str = "dm";
pub const ROLE_OWNER: &str = "owner";
pub const ROLE_MEMBER: &str = "member";

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AccountRecord {
    pub id: String,
    pub handle: Option<String>,
    pub display_name: String,
    pub created_at: u64,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MemberSummary {
    pub account_id: String,
    pub handle: Option<String>,
    pub display_name: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ConversationSummary {
    pub id: String,
    pub kind: String,
    pub workspace_id: Option<String>,
    pub name: Option<String>,
    pub last_sequence: u64,
    pub delivered_sequence: u64,
    pub read_sequence: u64,
    pub members: Vec<MemberSummary>,
    pub receipts: Vec<Receipt>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct StoredMessage {
    pub conversation_id: String,
    pub sequence: u64,
    pub id: String,
    pub sender_account_id: String,
    pub sender_device_public_key: [u8; 32],
    pub client_id: String,
    pub sent_at: u64,
    pub text: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Receipt {
    pub conversation_id: String,
    pub account_id: String,
    pub delivered_sequence: u64,
    pub read_sequence: u64,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AppendOutcome {
    pub message: StoredMessage,
    pub duplicate: bool,
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
            );
            CREATE TABLE IF NOT EXISTS workspaces (
                id TEXT PRIMARY KEY,
                name TEXT NOT NULL,
                created_at INTEGER NOT NULL
            );
            CREATE TABLE IF NOT EXISTS workspace_members (
                workspace_id TEXT NOT NULL REFERENCES workspaces(id),
                account_id TEXT NOT NULL REFERENCES accounts(id),
                role TEXT NOT NULL,
                PRIMARY KEY (workspace_id, account_id)
            );
            CREATE TABLE IF NOT EXISTS conversations (
                id TEXT PRIMARY KEY,
                kind TEXT NOT NULL,
                workspace_id TEXT REFERENCES workspaces(id),
                name TEXT,
                dm_key TEXT UNIQUE,
                created_at INTEGER NOT NULL,
                last_sequence INTEGER NOT NULL DEFAULT 0,
                UNIQUE (workspace_id, name)
            );
            CREATE TABLE IF NOT EXISTS conversation_members (
                conversation_id TEXT NOT NULL REFERENCES conversations(id),
                account_id TEXT NOT NULL REFERENCES accounts(id),
                delivered_sequence INTEGER NOT NULL DEFAULT 0,
                read_sequence INTEGER NOT NULL DEFAULT 0,
                PRIMARY KEY (conversation_id, account_id)
            );
            CREATE INDEX IF NOT EXISTS conversation_members_by_account
                ON conversation_members(account_id);
            CREATE TABLE IF NOT EXISTS messages (
                conversation_id TEXT NOT NULL REFERENCES conversations(id),
                sequence INTEGER NOT NULL,
                id TEXT NOT NULL UNIQUE,
                sender_account_id TEXT NOT NULL REFERENCES accounts(id),
                sender_device_public_key BLOB NOT NULL,
                client_id TEXT NOT NULL,
                sent_at INTEGER NOT NULL,
                nonce BLOB NOT NULL,
                ciphertext BLOB NOT NULL,
                PRIMARY KEY (conversation_id, sequence),
                UNIQUE (sender_device_public_key, client_id)
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
        match version {
            None => {
                self.connection.execute(
                    "INSERT INTO meta (key, value) VALUES ('schema_version', ?1)",
                    params![SCHEMA_VERSION.to_string().into_bytes()],
                )?;
            }
            Some(value) if value == SCHEMA_VERSION.to_string().into_bytes() => {}
            Some(value) => {
                return Err(StorageError::UnsupportedSchema(
                    String::from_utf8_lossy(&value).into_owned(),
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

    fn message_associated_data(conversation_id: &str, sequence: u64, message_id: &str) -> Vec<u8> {
        let mut data = Vec::with_capacity(conversation_id.len() + 8 + message_id.len() + 2);
        data.extend_from_slice(conversation_id.as_bytes());
        data.push(0);
        data.extend_from_slice(&sequence.to_be_bytes());
        data.push(0);
        data.extend_from_slice(message_id.as_bytes());
        data
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

    // ----- workspaces -----

    /// Only workspaces visible to this account, including empty workspaces.
    pub fn workspaces_for(
        &self,
        account_id: &str,
    ) -> Result<Vec<(String, String, String)>, StorageError> {
        let mut statement = self.connection.prepare(
            "SELECT w.id, w.name, m.role FROM workspaces w JOIN workspace_members m ON m.workspace_id = w.id WHERE m.account_id = ?1 ORDER BY w.created_at, w.id",
        )?;
        let rows = statement.query_map(params![account_id], |row| {
            Ok((row.get(0)?, row.get(1)?, row.get(2)?))
        })?;
        rows.collect::<Result<_, _>>().map_err(StorageError::from)
    }

    pub fn create_workspace(
        &mut self,
        name: &str,
        owner_account_id: &str,
        now: u64,
    ) -> Result<String, StorageError> {
        let id = random_id()?;
        let transaction = self.connection.transaction()?;
        transaction.execute(
            "INSERT INTO workspaces (id, name, created_at) VALUES (?1, ?2, ?3)",
            params![id, name, to_i64(now)],
        )?;
        transaction.execute(
            "INSERT INTO workspace_members (workspace_id, account_id, role) VALUES (?1, ?2, ?3)",
            params![id, owner_account_id, ROLE_OWNER],
        )?;
        transaction.commit()?;
        Ok(id)
    }

    pub fn workspace_role(
        &self,
        workspace_id: &str,
        account_id: &str,
    ) -> Result<Option<String>, StorageError> {
        self.connection
            .query_row(
                "SELECT role FROM workspace_members WHERE workspace_id = ?1 AND account_id = ?2",
                params![workspace_id, account_id],
                |row| row.get(0),
            )
            .optional()
            .map_err(StorageError::from)
    }

    /// Add an account to a workspace and to every existing channel in it.
    /// Returns the channel identifiers the account was added to.
    pub fn add_workspace_member(
        &mut self,
        workspace_id: &str,
        account_id: &str,
    ) -> Result<Vec<String>, StorageError> {
        let transaction = self.connection.transaction()?;
        let inserted = transaction.execute(
            "INSERT OR IGNORE INTO workspace_members (workspace_id, account_id, role) VALUES (?1, ?2, ?3)",
            params![workspace_id, account_id, ROLE_MEMBER],
        )?;
        if inserted == 0 {
            transaction.commit()?;
            return Ok(Vec::new());
        }
        let channels: Vec<String> = {
            let mut statement = transaction
                .prepare("SELECT id FROM conversations WHERE workspace_id = ?1 AND kind = ?2")?;
            let rows =
                statement.query_map(params![workspace_id, KIND_CHANNEL], |row| row.get(0))?;
            rows.collect::<Result<_, _>>()?
        };
        for channel in &channels {
            transaction.execute(
                "INSERT OR IGNORE INTO conversation_members (conversation_id, account_id) VALUES (?1, ?2)",
                params![channel, account_id],
            )?;
        }
        transaction.commit()?;
        Ok(channels)
    }

    pub fn workspace_member_ids(&self, workspace_id: &str) -> Result<Vec<String>, StorageError> {
        let mut statement = self.connection.prepare(
            "SELECT account_id FROM workspace_members WHERE workspace_id = ?1 ORDER BY account_id",
        )?;
        let rows = statement.query_map(params![workspace_id], |row| row.get(0))?;
        rows.collect::<Result<_, _>>().map_err(StorageError::from)
    }

    // ----- conversations -----

    pub fn create_channel(
        &mut self,
        workspace_id: &str,
        name: &str,
        now: u64,
    ) -> Result<String, StorageError> {
        let id = random_id()?;
        let transaction = self.connection.transaction()?;
        match transaction.execute(
            "INSERT INTO conversations (id, kind, workspace_id, name, dm_key, created_at)
             VALUES (?1, ?2, ?3, ?4, NULL, ?5)",
            params![id, KIND_CHANNEL, workspace_id, name, to_i64(now)],
        ) {
            Ok(_) => {}
            Err(error) if is_constraint(&error) => return Err(StorageError::NameTaken),
            Err(error) => return Err(error.into()),
        }
        transaction.execute(
            "INSERT INTO conversation_members (conversation_id, account_id)
             SELECT ?1, account_id FROM workspace_members WHERE workspace_id = ?2",
            params![id, workspace_id],
        )?;
        transaction.commit()?;
        Ok(id)
    }

    /// Find or create the direct conversation between two accounts.
    pub fn open_dm(
        &mut self,
        first: &str,
        second: &str,
        now: u64,
    ) -> Result<(String, bool), StorageError> {
        let (low, high) = if first <= second {
            (first, second)
        } else {
            (second, first)
        };
        let dm_key = format!("{low}\0{high}");
        let existing: Option<String> = self
            .connection
            .query_row(
                "SELECT id FROM conversations WHERE dm_key = ?1",
                params![dm_key],
                |row| row.get(0),
            )
            .optional()?;
        if let Some(id) = existing {
            return Ok((id, false));
        }
        let id = random_id()?;
        let transaction = self.connection.transaction()?;
        transaction.execute(
            "INSERT INTO conversations (id, kind, workspace_id, name, dm_key, created_at)
             VALUES (?1, ?2, NULL, NULL, ?3, ?4)",
            params![id, KIND_DM, dm_key, to_i64(now)],
        )?;
        for member in [low, high] {
            transaction.execute(
                "INSERT OR IGNORE INTO conversation_members (conversation_id, account_id) VALUES (?1, ?2)",
                params![id, member],
            )?;
        }
        transaction.commit()?;
        Ok((id, true))
    }

    pub fn is_member(&self, conversation_id: &str, account_id: &str) -> Result<bool, StorageError> {
        let found: Option<i64> = self
            .connection
            .query_row(
                "SELECT 1 FROM conversation_members WHERE conversation_id = ?1 AND account_id = ?2",
                params![conversation_id, account_id],
                |row| row.get(0),
            )
            .optional()?;
        Ok(found.is_some())
    }

    pub fn member_ids(&self, conversation_id: &str) -> Result<Vec<String>, StorageError> {
        let mut statement = self.connection.prepare(
            "SELECT account_id FROM conversation_members WHERE conversation_id = ?1 ORDER BY account_id",
        )?;
        let rows = statement.query_map(params![conversation_id], |row| row.get(0))?;
        rows.collect::<Result<_, _>>().map_err(StorageError::from)
    }

    pub fn conversation(
        &self,
        conversation_id: &str,
        viewer_account_id: &str,
    ) -> Result<Option<ConversationSummary>, StorageError> {
        let base = self
            .connection
            .query_row(
                "SELECT c.id, c.kind, c.workspace_id, c.name, c.last_sequence,
                        m.delivered_sequence, m.read_sequence
                 FROM conversations c
                 JOIN conversation_members m ON m.conversation_id = c.id
                 WHERE c.id = ?1 AND m.account_id = ?2",
                params![conversation_id, viewer_account_id],
                conversation_row,
            )
            .optional()?;
        match base {
            None => Ok(None),
            Some(mut summary) => {
                summary.members = self.members(&summary.id)?;
                summary.receipts = self.receipts(&summary.id)?;
                Ok(Some(summary))
            }
        }
    }

    pub fn conversations_for(
        &self,
        viewer_account_id: &str,
    ) -> Result<Vec<ConversationSummary>, StorageError> {
        let mut statement = self.connection.prepare(
            "SELECT c.id, c.kind, c.workspace_id, c.name, c.last_sequence,
                    m.delivered_sequence, m.read_sequence
             FROM conversations c
             JOIN conversation_members m ON m.conversation_id = c.id
             WHERE m.account_id = ?1
             ORDER BY c.created_at, c.id",
        )?;
        let rows = statement.query_map(params![viewer_account_id], conversation_row)?;
        let mut summaries: Vec<ConversationSummary> = rows.collect::<Result<_, _>>()?;
        for summary in &mut summaries {
            summary.members = self.members(&summary.id)?;
            summary.receipts = self.receipts(&summary.id)?;
        }
        Ok(summaries)
    }

    fn members(&self, conversation_id: &str) -> Result<Vec<MemberSummary>, StorageError> {
        let mut statement = self.connection.prepare(
            "SELECT a.id, a.handle, a.display_name
             FROM conversation_members m JOIN accounts a ON a.id = m.account_id
             WHERE m.conversation_id = ?1 ORDER BY a.id",
        )?;
        let rows = statement.query_map(params![conversation_id], |row| {
            Ok(MemberSummary {
                account_id: row.get(0)?,
                handle: row.get(1)?,
                display_name: row.get(2)?,
            })
        })?;
        rows.collect::<Result<_, _>>().map_err(StorageError::from)
    }

    // ----- messages -----

    /// Append a message or return the message previously stored for the same
    /// device and `client_id`. The sender's own receipt advances to the new
    /// sequence.
    pub fn append_message(
        &mut self,
        conversation_id: &str,
        sender_account_id: &str,
        sender_device_public_key: &[u8; 32],
        client_id: &str,
        text: &str,
        now: u64,
    ) -> Result<AppendOutcome, StorageError> {
        if let Some(existing) = self.message_by_client_id(sender_device_public_key, client_id)? {
            if existing.conversation_id != conversation_id {
                return Err(StorageError::ClientIdReused);
            }
            return Ok(AppendOutcome {
                message: existing,
                duplicate: true,
            });
        }
        let message_id = random_id()?;
        let transaction = self.connection.transaction()?;
        let last: i64 = transaction.query_row(
            "SELECT last_sequence FROM conversations WHERE id = ?1",
            params![conversation_id],
            |row| row.get(0),
        )?;
        let sequence = last + 1;
        let associated =
            Self::message_associated_data(conversation_id, from_i64(sequence), &message_id);
        let sealed = seal_with(&self.key, &associated, text.as_bytes())?;
        let (nonce, ciphertext) = sealed.split_at(NONCE_BYTES);
        transaction.execute(
            "INSERT INTO messages (conversation_id, sequence, id, sender_account_id,
                                   sender_device_public_key, client_id, sent_at, nonce, ciphertext)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)",
            params![
                conversation_id,
                sequence,
                message_id,
                sender_account_id,
                sender_device_public_key.as_slice(),
                client_id,
                to_i64(now),
                nonce,
                ciphertext
            ],
        )?;
        transaction.execute(
            "UPDATE conversations SET last_sequence = ?2 WHERE id = ?1",
            params![conversation_id, sequence],
        )?;
        transaction.execute(
            "UPDATE conversation_members
             SET delivered_sequence = MAX(delivered_sequence, ?3),
                 read_sequence = MAX(read_sequence, ?3)
             WHERE conversation_id = ?1 AND account_id = ?2",
            params![conversation_id, sender_account_id, sequence],
        )?;
        transaction.commit()?;
        Ok(AppendOutcome {
            message: StoredMessage {
                conversation_id: conversation_id.to_owned(),
                sequence: from_i64(sequence),
                id: message_id,
                sender_account_id: sender_account_id.to_owned(),
                sender_device_public_key: *sender_device_public_key,
                client_id: client_id.to_owned(),
                sent_at: now,
                text: text.to_owned(),
            },
            duplicate: false,
        })
    }

    fn message_by_client_id(
        &self,
        sender_device_public_key: &[u8; 32],
        client_id: &str,
    ) -> Result<Option<StoredMessage>, StorageError> {
        let row = self
            .connection
            .query_row(
                "SELECT conversation_id, sequence, id, sender_account_id, sender_device_public_key,
                        client_id, sent_at, nonce, ciphertext
                 FROM messages WHERE sender_device_public_key = ?1 AND client_id = ?2",
                params![sender_device_public_key.as_slice(), client_id],
                raw_message_row,
            )
            .optional()?;
        row.map(|raw| self.decode_message(raw)).transpose()
    }

    /// Messages before `before_sequence` (exclusive) in ascending order, at
    /// most `limit` of them.
    pub fn history(
        &self,
        conversation_id: &str,
        before_sequence: u64,
        limit: u32,
    ) -> Result<Vec<StoredMessage>, StorageError> {
        let mut statement = self.connection.prepare(
            "SELECT conversation_id, sequence, id, sender_account_id, sender_device_public_key,
                    client_id, sent_at, nonce, ciphertext
             FROM messages WHERE conversation_id = ?1 AND sequence < ?2
             ORDER BY sequence DESC LIMIT ?3",
        )?;
        let rows = statement.query_map(
            params![conversation_id, to_i64(before_sequence), i64::from(limit)],
            raw_message_row,
        )?;
        let mut messages = rows
            .map(|raw| self.decode_message(raw?))
            .collect::<Result<Vec<_>, _>>()?;
        messages.reverse();
        Ok(messages)
    }

    fn decode_message(&self, raw: RawMessage) -> Result<StoredMessage, StorageError> {
        let device: [u8; 32] = raw
            .sender_device_public_key
            .try_into()
            .map_err(|_| StorageError::Corrupt)?;
        let sequence = from_i64(raw.sequence);
        let associated = Self::message_associated_data(&raw.conversation_id, sequence, &raw.id);
        let mut sealed = raw.nonce;
        sealed.extend_from_slice(&raw.ciphertext);
        let text = self.open_sealed(&associated, &sealed)?;
        Ok(StoredMessage {
            conversation_id: raw.conversation_id,
            sequence,
            id: raw.id,
            sender_account_id: raw.sender_account_id,
            sender_device_public_key: device,
            client_id: raw.client_id,
            sent_at: from_i64(raw.sent_at),
            text: String::from_utf8(text).map_err(|_| StorageError::Corrupt)?,
        })
    }

    /// Raw stored bytes for one message, for tests that prove content is
    /// not stored in the clear.
    pub fn raw_ciphertext(&self, message_id: &str) -> Result<Option<Vec<u8>>, StorageError> {
        self.connection
            .query_row(
                "SELECT ciphertext FROM messages WHERE id = ?1",
                params![message_id],
                |row| row.get(0),
            )
            .optional()
            .map_err(StorageError::from)
    }

    // ----- receipts -----

    /// Advance the viewer's delivered (and optionally read) sequence. Values
    /// never move backwards and may not exceed the conversation's last
    /// sequence.
    pub fn advance_receipt(
        &mut self,
        conversation_id: &str,
        account_id: &str,
        sequence: u64,
        read: bool,
    ) -> Result<Receipt, StorageError> {
        let transaction = self.connection.transaction()?;
        let last: i64 = transaction.query_row(
            "SELECT last_sequence FROM conversations WHERE id = ?1",
            params![conversation_id],
            |row| row.get(0),
        )?;
        if to_i64(sequence) > last {
            return Err(StorageError::SequenceAhead);
        }
        let read_sequence = if read { to_i64(sequence) } else { 0 };
        let updated = transaction.execute(
            "UPDATE conversation_members
             SET delivered_sequence = MAX(delivered_sequence, ?3),
                 read_sequence = MAX(read_sequence, ?4)
             WHERE conversation_id = ?1 AND account_id = ?2",
            params![conversation_id, account_id, to_i64(sequence), read_sequence],
        )?;
        if updated == 0 {
            return Err(StorageError::NotFound);
        }
        let receipt = transaction.query_row(
            "SELECT delivered_sequence, read_sequence FROM conversation_members
             WHERE conversation_id = ?1 AND account_id = ?2",
            params![conversation_id, account_id],
            |row| {
                Ok(Receipt {
                    conversation_id: conversation_id.to_owned(),
                    account_id: account_id.to_owned(),
                    delivered_sequence: from_i64(row.get(0)?),
                    read_sequence: from_i64(row.get(1)?),
                })
            },
        )?;
        transaction.commit()?;
        Ok(receipt)
    }

    pub fn receipts(&self, conversation_id: &str) -> Result<Vec<Receipt>, StorageError> {
        let mut statement = self.connection.prepare(
            "SELECT account_id, delivered_sequence, read_sequence FROM conversation_members
             WHERE conversation_id = ?1 ORDER BY account_id",
        )?;
        let rows = statement.query_map(params![conversation_id], |row| {
            Ok(Receipt {
                conversation_id: conversation_id.to_owned(),
                account_id: row.get(0)?,
                delivered_sequence: from_i64(row.get(1)?),
                read_sequence: from_i64(row.get(2)?),
            })
        })?;
        rows.collect::<Result<_, _>>().map_err(StorageError::from)
    }
}

struct RawMessage {
    conversation_id: String,
    sequence: i64,
    id: String,
    sender_account_id: String,
    sender_device_public_key: Vec<u8>,
    client_id: String,
    sent_at: i64,
    nonce: Vec<u8>,
    ciphertext: Vec<u8>,
}

fn raw_message_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<RawMessage> {
    Ok(RawMessage {
        conversation_id: row.get(0)?,
        sequence: row.get(1)?,
        id: row.get(2)?,
        sender_account_id: row.get(3)?,
        sender_device_public_key: row.get(4)?,
        client_id: row.get(5)?,
        sent_at: row.get(6)?,
        nonce: row.get(7)?,
        ciphertext: row.get(8)?,
    })
}

fn account_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<AccountRecord> {
    Ok(AccountRecord {
        id: row.get(0)?,
        handle: row.get(1)?,
        display_name: row.get(2)?,
        created_at: from_i64(row.get(3)?),
    })
}

fn conversation_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<ConversationSummary> {
    Ok(ConversationSummary {
        id: row.get(0)?,
        kind: row.get(1)?,
        workspace_id: row.get(2)?,
        name: row.get(3)?,
        last_sequence: from_i64(row.get(4)?),
        delivered_sequence: from_i64(row.get(5)?),
        read_sequence: from_i64(row.get(6)?),
        members: Vec::new(),
        receipts: Vec::new(),
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
    NameTaken,
    ClientIdReused,
    SequenceAhead,
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
            Self::NameTaken => formatter.write_str("name already used in this workspace"),
            Self::ClientIdReused => {
                formatter.write_str("client_id was already used for another conversation")
            }
            Self::SequenceAhead => {
                formatter.write_str("sequence is ahead of the conversation's last message")
            }
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
    fn channels_membership_and_idempotent_messages() {
        let mut storage = storage();
        let ada = storage.create_account(&[1_u8; 32], "Ada", 1).unwrap();
        let bob = storage.create_account(&[2_u8; 32], "Bob", 1).unwrap();
        let workspace = storage.create_workspace("Team", &ada.id, 2).unwrap();
        let general = storage.create_channel(&workspace, "general", 3).unwrap();
        assert!(matches!(
            storage.create_channel(&workspace, "general", 3),
            Err(StorageError::NameTaken)
        ));
        assert!(storage.is_member(&general, &ada.id).unwrap());
        assert!(!storage.is_member(&general, &bob.id).unwrap());
        let joined = storage.add_workspace_member(&workspace, &bob.id).unwrap();
        assert_eq!(joined, vec![general.clone()]);
        assert!(storage.is_member(&general, &bob.id).unwrap());
        assert!(
            storage
                .add_workspace_member(&workspace, &bob.id)
                .unwrap()
                .is_empty()
        );

        let first = storage
            .append_message(&general, &ada.id, &[1_u8; 32], "c1", "hello", 5)
            .unwrap();
        assert_eq!(first.message.sequence, 1);
        assert!(!first.duplicate);
        let again = storage
            .append_message(&general, &ada.id, &[1_u8; 32], "c1", "hello", 6)
            .unwrap();
        assert!(again.duplicate);
        assert_eq!(again.message, first.message);
        assert!(matches!(
            storage.append_message("other", &ada.id, &[1_u8; 32], "c1", "hello", 6),
            Err(StorageError::ClientIdReused)
        ));
        let second = storage
            .append_message(&general, &bob.id, &[2_u8; 32], "c1", "hi", 7)
            .unwrap();
        assert_eq!(second.message.sequence, 2);

        let history = storage.history(&general, u64::MAX, 10).unwrap();
        assert_eq!(
            history.iter().map(|m| m.sequence).collect::<Vec<_>>(),
            vec![1, 2]
        );
        assert_eq!(history[0].text, "hello");
        let page = storage.history(&general, 2, 10).unwrap();
        assert_eq!(page.len(), 1);

        let raw = storage.raw_ciphertext(&first.message.id).unwrap().unwrap();
        assert!(!raw.windows(5).any(|window| window == b"hello"));

        let summary = storage.conversation(&general, &bob.id).unwrap().unwrap();
        assert_eq!(summary.last_sequence, 2);
        assert_eq!(summary.read_sequence, 2, "sender's own receipt advances");
        let ada_view = storage.conversation(&general, &ada.id).unwrap().unwrap();
        assert_eq!(ada_view.read_sequence, 1);
        let receipt = storage
            .advance_receipt(&general, &ada.id, 2, false)
            .unwrap();
        assert_eq!((receipt.delivered_sequence, receipt.read_sequence), (2, 1));
        let receipt = storage.advance_receipt(&general, &ada.id, 1, true).unwrap();
        assert_eq!((receipt.delivered_sequence, receipt.read_sequence), (2, 1));
        assert!(matches!(
            storage.advance_receipt(&general, &ada.id, 3, true),
            Err(StorageError::SequenceAhead)
        ));
    }

    #[test]
    fn direct_conversations_are_unique_per_pair() {
        let mut storage = storage();
        let ada = storage.create_account(&[1_u8; 32], "Ada", 1).unwrap();
        let bob = storage.create_account(&[2_u8; 32], "Bob", 1).unwrap();
        let (first, created) = storage.open_dm(&ada.id, &bob.id, 2).unwrap();
        assert!(created);
        let (second, created) = storage.open_dm(&bob.id, &ada.id, 3).unwrap();
        assert!(!created);
        assert_eq!(first, second);
        let list = storage.conversations_for(&ada.id).unwrap();
        assert_eq!(list.len(), 1);
        assert_eq!(list[0].members.len(), 2);
    }

    #[test]
    fn wrong_storage_key_is_refused() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("messages.db");
        drop(Storage::open(&path, Zeroizing::new([1_u8; 32])).unwrap());
        assert!(matches!(
            Storage::open(&path, Zeroizing::new([2_u8; 32])),
            Err(StorageError::WrongKey)
        ));
        drop(Storage::open(&path, Zeroizing::new([1_u8; 32])).unwrap());
    }
}
