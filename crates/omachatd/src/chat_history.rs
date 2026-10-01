//! Bounded sealed UI cache. Transport queues remain the delivery authority.
use crate::CoreError;
use omachat_store::{SealedStore, StoreError};
use serde_json::Value;

const RECORD: &str = "chat-history-v1";
const MAX_BYTES: usize = 32 * 1024;
const MAX_MESSAGES: usize = 128;
const MAX_AGE: u64 = 24 * 60 * 60;

#[derive(Default)]
pub(crate) struct ChatHistory {
    messages: Vec<Value>,
}

impl ChatHistory {
    pub fn load(store: &SealedStore, now: u64) -> Result<Self, CoreError> {
        let messages = match store.read(RECORD) {
            Ok(bytes) => {
                if bytes.len() > MAX_BYTES {
                    return Err(CoreError::Encoding);
                }
                serde_json::from_slice(&bytes).map_err(|_| CoreError::Encoding)?
            }
            Err(StoreError::RecordNotFound) => Vec::new(),
            Err(error) => return Err(CoreError::Store(error)),
        };
        let mut history = Self { messages };
        history.expire(now);
        history.persist(store)?;
        Ok(history)
    }

    fn expire(&mut self, now: u64) {
        self.messages.retain(|message| {
            message["cached_at"]
                .as_u64()
                .is_some_and(|at| at <= now && now.saturating_sub(at) < MAX_AGE)
        });
    }

    pub fn snapshot(&mut self, store: &SealedStore, now: u64) -> Result<Vec<Value>, CoreError> {
        self.expire(now);
        self.persist(store)?;
        Ok(self.messages.clone())
    }

    pub fn update(
        &mut self,
        store: &SealedStore,
        mut payload: Value,
        now: u64,
    ) -> Result<(), CoreError> {
        self.expire(now);
        let Some(id) = payload["id"].as_str() else {
            return Ok(());
        };
        let index = self
            .messages
            .iter()
            .position(|message| message["id"].as_str() == Some(id));
        if payload["deleted"].as_bool() == Some(true) {
            if let Some(index) = index {
                self.messages.remove(index);
            }
        } else if let Some(index) = index {
            // Relay echoes and retry acknowledgements enrich, never duplicate,
            // the original message or reset its local retention deadline.
            let old = self.messages[index]
                .as_object_mut()
                .ok_or(CoreError::Encoding)?;
            if payload["outgoing"] == true {
                old.insert("outgoing".into(), true.into());
                old.insert("sender".into(), "you".into());
            }
            if let Some(delivery) = payload.get("delivery")
                && delivery != "received"
            {
                old.insert("delivery".into(), delivery.clone());
            }
        } else if payload["text"].is_string() && payload["conversation"].is_string() {
            payload["cached_at"] = now.into();
            self.messages.push(payload);
        }
        while self.messages.len() > MAX_MESSAGES
            || serde_json::to_vec(&self.messages)
                .map_err(|_| CoreError::Encoding)?
                .len()
                > MAX_BYTES
        {
            self.messages.remove(0);
        }
        self.persist(store)
    }

    pub fn clear(&mut self) {
        self.messages.clear();
    }

    fn persist(&self, store: &SealedStore) -> Result<(), CoreError> {
        store
            .write(
                RECORD,
                &serde_json::to_vec(&self.messages).map_err(|_| CoreError::Encoding)?,
            )
            .map_err(CoreError::Store)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use omachat_store::RequestedProvider;
    use serde_json::json;

    #[tokio::test]
    async fn sealed_history_restarts_deduplicates_updates_expires_and_stays_bounded() {
        let dir = tempfile::tempdir().unwrap();
        let store = SealedStore::open(dir.path(), RequestedProvider::File)
            .await
            .unwrap();
        let mut history = ChatHistory::load(&store, 100).unwrap();
        history.update(&store, json!({"id":"one", "conversation":"dm:peer", "text":"secret plaintext", "delivery":"queued"}), 100).unwrap();
        history
            .update(&store, json!({"id":"one", "delivery":"stored"}), 101)
            .unwrap();
        drop(history);
        let mut history = ChatHistory::load(&store, 102).unwrap();
        let snapshot = history.snapshot(&store, 102).unwrap();
        assert_eq!(snapshot.len(), 1);
        assert_eq!(snapshot[0]["delivery"], "stored");
        let sealed = std::fs::read(dir.path().join("records").join(RECORD)).unwrap();
        assert!(!sealed.windows(16).any(|w| w == b"secret plaintext"));
        for i in 0..200 {
            history
                .update(
                    &store,
                    json!({"id":i.to_string(), "conversation":"#gcpvj", "text":"x".repeat(4096)}),
                    103,
                )
                .unwrap();
        }
        let snapshot = history.snapshot(&store, 103).unwrap();
        assert!(snapshot.len() <= MAX_MESSAGES);
        assert!(serde_json::to_vec(&snapshot).unwrap().len() <= MAX_BYTES);
        assert!(history.snapshot(&store, 103 + MAX_AGE).unwrap().is_empty());
    }
}
