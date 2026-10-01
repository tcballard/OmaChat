//! Daemon-owned sealed drafts. Call only under the core storage transaction.
use crate::CoreError;
use omachat_proto::ipc::Command;
use omachat_store::{SealedStore, StoreError};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::collections::BTreeMap;

const RECORD: &str = "chat-drafts-v1";
const MAX_DRAFTS: usize = 64;
const MAX_BYTES: usize = 512 * 1024;
const MAX_REVISION: u64 = (1_u64 << 53) - 1;

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Draft {
    text: String,
    revision: u64,
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Drafts {
    version: u8,
    generation: u64,
    entries: BTreeMap<String, Draft>,
}

fn valid_conversation(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 256
        && !value.chars().any(char::is_control)
        && value.trim() == value
        && (value.starts_with("dm:")
            || value.starts_with("room:")
            || value.starts_with('#')
            || value.strip_prefix("hosted:").is_some_and(|id| {
                !id.is_empty()
                    && id.len() <= 128
                    && id
                        .bytes()
                        .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
            }))
}

impl Drafts {
    fn load(store: &SealedStore) -> Result<Self, CoreError> {
        let bytes = match store.read(RECORD) {
            Ok(bytes) => bytes,
            Err(StoreError::RecordNotFound) => {
                return Ok(Self {
                    version: 1,
                    generation: 0,
                    entries: BTreeMap::new(),
                });
            }
            Err(error) => return Err(CoreError::Store(error)),
        };
        if bytes.len() > MAX_BYTES {
            return Err(CoreError::Encoding);
        }
        let value: Self = serde_json::from_slice(&bytes).map_err(|_| CoreError::Encoding)?;
        if value.version != 1
            || value.generation > MAX_REVISION
            || value.entries.len() > MAX_DRAFTS
            || value.entries.iter().any(|(id, entry)| {
                !valid_conversation(id)
                    || entry.text.is_empty()
                    || entry.text.len() > 4096
                    || entry.revision == 0
                    || entry.revision > value.generation
            })
        {
            return Err(CoreError::Encoding);
        }
        Ok(value)
    }

    fn get(&self, conversation: &str) -> Value {
        let entry = self.entries.get(conversation);
        json!({
            "conversation": conversation,
            "text": entry.map_or("", |draft| draft.text.as_str()),
            // An absent draft uses the global generation, preventing a stale
            // create after another client created and then deleted this draft.
            "revision": entry.map_or(self.generation, |draft| draft.revision),
        })
    }

    fn save(
        &mut self,
        store: &SealedStore,
        conversation: String,
        text: String,
        expected_revision: u64,
    ) -> Result<Value, CoreError> {
        if !valid_conversation(&conversation)
            || text.len() > 4096
            || expected_revision > MAX_REVISION
        {
            return Err(CoreError::InvalidDraft);
        }
        let mut current = self.get(&conversation);
        if current["revision"] != expected_revision {
            current["saved"] = false.into();
            return Ok(current);
        }
        if current["text"] == text {
            current["saved"] = true.into();
            return Ok(current);
        }
        if (!text.is_empty()
            && !self.entries.contains_key(&conversation)
            && self.entries.len() == MAX_DRAFTS)
            || self.generation == MAX_REVISION
        {
            return Err(CoreError::DraftCapacity);
        }
        self.generation += 1;
        if text.is_empty() {
            self.entries.remove(&conversation);
        } else {
            self.entries.insert(
                conversation.clone(),
                Draft {
                    text,
                    revision: self.generation,
                },
            );
        }
        let bytes = serde_json::to_vec(self).map_err(|_| CoreError::Encoding)?;
        if bytes.len() > MAX_BYTES {
            return Err(CoreError::DraftCapacity);
        }
        store.write(RECORD, &bytes).map_err(CoreError::Store)?;
        let mut result = self.get(&conversation);
        result["saved"] = true.into();
        Ok(result)
    }
}

pub(crate) fn dispatch(store: &SealedStore, command: Command) -> Result<Value, CoreError> {
    let mut drafts = Drafts::load(store)?;
    match command {
        Command::ListDrafts => Ok(json!({"drafts": drafts.entries.iter().map(|(id, draft)| {
            json!({"conversation": id, "revision": draft.revision})
        }).collect::<Vec<_>>()})),
        Command::GetDraft { conversation } => {
            if !valid_conversation(&conversation) {
                return Err(CoreError::InvalidDraft);
            }
            Ok(drafts.get(&conversation))
        }
        Command::SaveDraft {
            conversation,
            text,
            expected_revision,
        } => drafts.save(store, conversation, text, expected_revision),
        _ => Err(CoreError::InvalidCommand),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use omachat_store::RequestedProvider;

    async fn fixture() -> (tempfile::TempDir, SealedStore) {
        let dir = tempfile::tempdir().unwrap();
        let store = SealedStore::open(dir.path(), RequestedProvider::File)
            .await
            .unwrap();
        (dir, store)
    }

    fn save(store: &SealedStore, id: &str, text: &str, revision: u64) -> Value {
        dispatch(
            store,
            Command::SaveDraft {
                conversation: id.into(),
                text: text.into(),
                expected_revision: revision,
            },
        )
        .unwrap()
    }

    #[tokio::test]
    async fn reopen_conflict_and_delete_do_not_lose_text() {
        let (dir, store) = fixture().await;
        let first = save(&store, "#gcpvj", "private draft sentinel", 0);
        assert_eq!(first["saved"], true);
        assert_eq!(save(&store, "#gcpvj", "stale client", 0)["saved"], false);
        let sealed = std::fs::read(dir.path().join("records").join(RECORD)).unwrap();
        assert!(!sealed.windows(22).any(|w| w == b"private draft sentinel"));
        drop(store);
        let store = SealedStore::open(dir.path(), RequestedProvider::File)
            .await
            .unwrap();
        let restored = Drafts::load(&store).unwrap().get("#gcpvj");
        assert_eq!(restored["text"], "private draft sentinel");
        let deleted = save(&store, "#gcpvj", "", restored["revision"].as_u64().unwrap());
        assert_eq!(deleted["saved"], true);
        assert_eq!(save(&store, "#gcpvj", "stale recreate", 0)["saved"], false);
        assert!(Drafts::load(&store).unwrap().entries.is_empty());
    }

    #[tokio::test]
    async fn corrupt_or_newer_records_are_never_replaced() {
        let (_dir, store) = fixture().await;
        for bytes in [
            b"broken".as_slice(),
            br#"{"version":2,"generation":0,"entries":{}}"#,
            br#"{"version":1,"generation":0,"entries":{},"unknown":true}"#,
        ] {
            store.write(RECORD, bytes).unwrap();
            assert!(Drafts::load(&store).is_err());
            assert!(
                dispatch(
                    &store,
                    Command::SaveDraft {
                        conversation: "#gcpvj".into(),
                        text: "replacement".into(),
                        expected_revision: 0,
                    },
                )
                .is_err()
            );
            assert_eq!(store.read(RECORD).unwrap(), bytes);
        }
    }

    #[tokio::test]
    async fn capacity_and_utf8_bounds_preserve_existing_drafts() {
        let (_dir, store) = fixture().await;
        for n in 0..MAX_DRAFTS {
            assert_eq!(
                save(&store, &format!("dm:{n}"), "hello", n as u64)["saved"],
                true
            );
        }
        let before = store.read(RECORD).unwrap();
        for (text, id) in [("more".into(), "dm:extra"), ("🙂".repeat(1025), "dm:0")] {
            assert!(
                dispatch(
                    &store,
                    Command::SaveDraft {
                        conversation: id.into(),
                        text,
                        expected_revision: if id == "dm:0" { 1 } else { MAX_DRAFTS as u64 },
                    },
                )
                .is_err()
            );
            assert_eq!(store.read(RECORD).unwrap(), before);
        }
        save(&store, "dm:0", "", 1);
        assert_eq!(
            save(&store, "dm:extra", "🙂".repeat(1024).as_str(), 65)["saved"],
            true
        );
        let listing = dispatch(&store, Command::ListDrafts).unwrap();
        assert!(serde_json::to_vec(&listing).unwrap().len() < 65536);
        assert!(!listing.to_string().contains("hello"));
    }
}
