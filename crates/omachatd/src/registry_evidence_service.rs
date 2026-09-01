use std::sync::Arc;

use ed25519_dalek::VerifyingKey;
use omachat_crypto::{AccountId, GlobalHandle};
use omachat_registry::HandleClaim;
use omachat_registry_transport::{
    RegistryEvidenceClient, RegistryEvidenceError, RegistryEvidenceResolution, RegistryTransport,
    RegistryWebSocketTransport,
};
use omachat_store::{RegistryCacheLookup, SealedStore};
use tokio::sync::Mutex;

use crate::{CoreError, RegistryClientConfig};

/// Daemon-owned registry transport and sealed evidence boundary.
///
/// One shared lock covers each transport exchange and cache mutation. This is
/// deliberately broader than a file-write lock: two clients must not both load
/// one cache snapshot and then persist divergent successors.
#[derive(Clone)]
pub struct RegistryEvidenceService<T = RegistryWebSocketTransport> {
    transport: T,
    pinned_public_key: [u8; 32],
    max_age_seconds: u64,
    operation: Arc<Mutex<()>>,
}

impl RegistryEvidenceService<RegistryWebSocketTransport> {
    pub fn from_config(config: &RegistryClientConfig) -> Result<Self, CoreError> {
        let transport = RegistryWebSocketTransport::new(&config.endpoint)
            .map_err(|_| CoreError::InvalidConfig)?;
        Self::with_transport(
            transport,
            config.pinned_public_key_bytes()?,
            config.max_age_seconds,
        )
    }
}

impl<T> RegistryEvidenceService<T> {
    pub fn with_transport(
        transport: T,
        pinned_public_key: [u8; 32],
        max_age_seconds: u64,
    ) -> Result<Self, CoreError> {
        let verifying_key =
            VerifyingKey::from_bytes(&pinned_public_key).map_err(|_| CoreError::InvalidConfig)?;
        if verifying_key.is_weak() || max_age_seconds == 0 {
            return Err(CoreError::InvalidConfig);
        }
        Ok(Self {
            transport,
            pinned_public_key,
            max_age_seconds,
            operation: Arc::new(Mutex::new(())),
        })
    }

    #[must_use]
    pub const fn pinned_public_key(&self) -> &[u8; 32] {
        &self.pinned_public_key
    }

    #[must_use]
    pub const fn max_age_seconds(&self) -> u64 {
        self.max_age_seconds
    }
}

impl<T: Clone + RegistryTransport> RegistryEvidenceService<T> {
    pub async fn claim_handle(
        &self,
        store: &SealedStore,
        claim: &HandleClaim,
        now: u64,
    ) -> Result<RegistryCacheLookup, RegistryEvidenceError<T::Error>> {
        let _operation = self.operation.lock().await;
        self.open(store)?.claim_handle(claim, now).await
    }

    pub async fn resolve_handle(
        &self,
        store: &SealedStore,
        handle: &GlobalHandle,
        now: u64,
    ) -> Result<RegistryEvidenceResolution<T::Error>, RegistryEvidenceError<T::Error>> {
        let _operation = self.operation.lock().await;
        self.open(store)?.resolve_handle(handle, now).await
    }

    pub async fn resolve_account(
        &self,
        store: &SealedStore,
        account_id: &AccountId,
        now: u64,
    ) -> Result<RegistryEvidenceResolution<T::Error>, RegistryEvidenceError<T::Error>> {
        let _operation = self.operation.lock().await;
        self.open(store)?.resolve_account(account_id, now).await
    }

    pub async fn cached_handle(
        &self,
        store: &SealedStore,
        handle: &GlobalHandle,
        now: u64,
    ) -> Result<RegistryCacheLookup, RegistryEvidenceError<T::Error>> {
        let _operation = self.operation.lock().await;
        Ok(self.open(store)?.cached_handle(handle, now))
    }

    pub async fn cached_account(
        &self,
        store: &SealedStore,
        account_id: &AccountId,
        now: u64,
    ) -> Result<RegistryCacheLookup, RegistryEvidenceError<T::Error>> {
        let _operation = self.operation.lock().await;
        Ok(self.open(store)?.cached_account(account_id, now))
    }

    pub async fn cached_nostr_public_key(
        &self,
        store: &SealedStore,
        public_key: &[u8; 32],
        now: u64,
    ) -> Result<RegistryCacheLookup, RegistryEvidenceError<T::Error>> {
        let _operation = self.operation.lock().await;
        Ok(self.open(store)?.cached_nostr_public_key(public_key, now))
    }

    fn open<'store>(
        &self,
        store: &'store SealedStore,
    ) -> Result<RegistryEvidenceClient<'store, T>, RegistryEvidenceError<T::Error>> {
        RegistryEvidenceClient::open(
            self.transport.clone(),
            store,
            self.pinned_public_key,
            self.max_age_seconds,
        )
    }
}
