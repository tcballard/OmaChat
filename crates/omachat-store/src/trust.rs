use crate::sealed::{SealedStore, StoreError};
use serde::{Deserialize, Serialize};
use std::{error::Error, fmt};

const PEER_TRUST_RECORD: &str = "peer-trust-v1";
const BLOCK_LIST_RECORD: &str = "block-list-v1";

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct PeerTrust {
    pub peer_id: String,
    pub noise_public_key: [u8; 32],
    pub signing_public_key: [u8; 32],
    pub favorite: bool,
    #[serde(default)]
    pub remote_favorite: bool,
    #[serde(default)]
    pub nostr_public_key: Option<String>,
    pub verified: bool,
    pub blocked: bool,
}

#[derive(Default, Deserialize, Serialize)]
struct PersistedPeerTrust {
    peers: Vec<PeerTrust>,
}

pub struct PeerTrustStore<'store> {
    store: &'store SealedStore,
    state: PersistedPeerTrust,
}

#[derive(Default, Deserialize, Serialize)]
struct PersistedBlockList {
    public_keys: Vec<String>,
}

pub struct BlockList<'store> {
    store: &'store SealedStore,
    state: PersistedBlockList,
}

impl<'store> BlockList<'store> {
    pub fn load(store: &'store SealedStore) -> Result<Self, TrustError> {
        let state = match store.read(BLOCK_LIST_RECORD) {
            Ok(bytes) => serde_json::from_slice(&bytes).map_err(|_| TrustError::Encoding)?,
            Err(StoreError::RecordNotFound) => PersistedBlockList::default(),
            Err(error) => return Err(TrustError::Store(error)),
        };
        Ok(Self { store, state })
    }

    pub fn block(&mut self, public_key: String) -> Result<(), TrustError> {
        if public_key.len() != 64 || hex::decode(&public_key).is_err() {
            return Err(TrustError::Invalid);
        }
        if !self.state.public_keys.contains(&public_key) {
            self.state.public_keys.push(public_key);
            self.state.public_keys.sort();
            self.persist()?;
        }
        Ok(())
    }

    pub fn unblock(&mut self, public_key: &str) -> Result<(), TrustError> {
        self.state.public_keys.retain(|item| item != public_key);
        self.persist()
    }

    #[must_use]
    pub fn contains(&self, public_key: &str) -> bool {
        self.state.public_keys.iter().any(|item| item == public_key)
    }

    #[must_use]
    pub fn keys(&self) -> &[String] {
        &self.state.public_keys
    }

    fn persist(&self) -> Result<(), TrustError> {
        self.store
            .write(
                BLOCK_LIST_RECORD,
                &serde_json::to_vec(&self.state).map_err(|_| TrustError::Encoding)?,
            )
            .map_err(TrustError::Store)
    }
}

impl<'store> PeerTrustStore<'store> {
    pub fn load(store: &'store SealedStore) -> Result<Self, TrustError> {
        let state = match store.read(PEER_TRUST_RECORD) {
            Ok(bytes) => serde_json::from_slice(&bytes).map_err(|_| TrustError::Encoding)?,
            Err(StoreError::RecordNotFound) => PersistedPeerTrust::default(),
            Err(error) => return Err(TrustError::Store(error)),
        };
        Ok(Self { store, state })
    }

    pub fn pin_authenticated(
        &mut self,
        peer_id: String,
        noise_public_key: [u8; 32],
        signing_public_key: [u8; 32],
    ) -> Result<bool, TrustError> {
        if peer_id.is_empty() || peer_id.len() > 128 {
            return Err(TrustError::Invalid);
        }
        if let Some(peer) = self.state.peers.iter().find(|peer| peer.peer_id == peer_id) {
            if peer.noise_public_key != noise_public_key
                || peer.signing_public_key != signing_public_key
            {
                return Err(TrustError::KeyMismatch);
            }
            return Ok(false);
        }
        self.state.peers.push(PeerTrust {
            peer_id,
            noise_public_key,
            signing_public_key,
            favorite: false,
            remote_favorite: false,
            nostr_public_key: None,
            verified: false,
            blocked: false,
        });
        self.persist()?;
        Ok(true)
    }

    pub fn set_favorite(&mut self, peer_id: &str, favorite: bool) -> Result<(), TrustError> {
        let peer = self.peer_mut(peer_id)?;
        peer.favorite = favorite;
        self.persist()
    }

    pub fn verify_key(
        &mut self,
        peer_id: &str,
        expected_signing_key: &[u8; 32],
    ) -> Result<(), TrustError> {
        let peer = self.peer_mut(peer_id)?;
        if &peer.signing_public_key != expected_signing_key {
            return Err(TrustError::KeyMismatch);
        }
        peer.verified = true;
        self.persist()
    }

    pub fn record_remote_favorite(
        &mut self,
        peer_id: &str,
        nostr_public_key: String,
    ) -> Result<(), TrustError> {
        if nostr_public_key.len() != 64 || hex::decode(&nostr_public_key).is_err() {
            return Err(TrustError::Invalid);
        }
        let peer = self.peer_mut(peer_id)?;
        peer.remote_favorite = true;
        peer.nostr_public_key = Some(nostr_public_key);
        self.persist()
    }

    #[must_use]
    pub fn mutual_favorite(&self, peer_id: &str) -> bool {
        self.state
            .peers
            .iter()
            .find(|peer| peer.peer_id == peer_id)
            .is_some_and(|peer| {
                peer.favorite && peer.remote_favorite && peer.nostr_public_key.is_some()
            })
    }

    pub fn set_blocked(&mut self, peer_id: &str, blocked: bool) -> Result<(), TrustError> {
        let peer = self.peer_mut(peer_id)?;
        peer.blocked = blocked;
        self.persist()
    }

    #[must_use]
    pub fn permits_content(&self, peer_id: &str) -> bool {
        self.state
            .peers
            .iter()
            .find(|peer| peer.peer_id == peer_id)
            .is_none_or(|peer| !peer.blocked)
    }

    #[must_use]
    pub fn peers(&self) -> &[PeerTrust] {
        &self.state.peers
    }

    fn peer_mut(&mut self, peer_id: &str) -> Result<&mut PeerTrust, TrustError> {
        self.state
            .peers
            .iter_mut()
            .find(|peer| peer.peer_id == peer_id)
            .ok_or(TrustError::NotMeshBound)
    }

    fn persist(&self) -> Result<(), TrustError> {
        self.store
            .write(
                PEER_TRUST_RECORD,
                &serde_json::to_vec(&self.state).map_err(|_| TrustError::Encoding)?,
            )
            .map_err(TrustError::Store)
    }
}

#[derive(Debug)]
pub enum TrustError {
    Store(StoreError),
    Encoding,
    Invalid,
    NotMeshBound,
    KeyMismatch,
}

impl fmt::Display for TrustError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "peer trust error: {self:?}")
    }
}

impl Error for TrustError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Store(error) => Some(error),
            _ => None,
        }
    }
}
