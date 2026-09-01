use std::sync::Arc;

use ed25519_dalek::VerifyingKey;
use omachat_crypto::{AccountId, GlobalHandle};
use omachat_registry::proof_bearing_claim::ProofBearingDeviceHandleClaim;
use omachat_registry_transport::{
    PrincipalRegistryEvidenceClient, PrincipalRegistryEvidenceError,
    PrincipalRegistryEvidenceResolution, RegistryTransport, RegistryWebSocketTransport,
};
use omachat_store::{PrincipalRegistryCacheLookup, SealedStore};
use tokio::sync::Mutex;

use crate::{CoreError, RegistryClientConfig, RegistryProtocol};

/// Daemon-owned serialized transport and sealed cache for proven principals.
#[derive(Clone)]
pub struct PrincipalRegistryEvidenceService<T = RegistryWebSocketTransport> {
    transport: T,
    pinned_public_key: [u8; 32],
    max_age_seconds: u64,
    operation: Arc<Mutex<()>>,
}

impl PrincipalRegistryEvidenceService<RegistryWebSocketTransport> {
    pub fn from_config(config: &RegistryClientConfig) -> Result<Self, CoreError> {
        if config.protocol != RegistryProtocol::PrincipalProofV1 {
            return Err(CoreError::InvalidConfig);
        }
        let transport = RegistryWebSocketTransport::new(&config.endpoint)
            .map_err(|_| CoreError::InvalidConfig)?;
        Self::with_transport(
            transport,
            config.pinned_public_key_bytes()?,
            config.max_age_seconds,
        )
    }
}

impl<T> PrincipalRegistryEvidenceService<T> {
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

impl<T: Clone + RegistryTransport> PrincipalRegistryEvidenceService<T> {
    pub async fn claim_device(
        &self,
        store: &SealedStore,
        claim: &ProofBearingDeviceHandleClaim,
        now: u64,
    ) -> Result<PrincipalRegistryCacheLookup, PrincipalRegistryEvidenceError<T::Error>> {
        let _operation = self.operation.lock().await;
        self.open(store)?.claim_device(claim, now).await
    }

    pub async fn resolve_public_key(
        &self,
        store: &SealedStore,
        public_key: &[u8; 32],
        now: u64,
    ) -> Result<
        PrincipalRegistryEvidenceResolution<T::Error>,
        PrincipalRegistryEvidenceError<T::Error>,
    > {
        let _operation = self.operation.lock().await;
        self.open(store)?.resolve_public_key(public_key, now).await
    }

    pub async fn resolve_handle(
        &self,
        store: &SealedStore,
        handle: &GlobalHandle,
        now: u64,
    ) -> Result<
        PrincipalRegistryEvidenceResolution<T::Error>,
        PrincipalRegistryEvidenceError<T::Error>,
    > {
        let _operation = self.operation.lock().await;
        self.open(store)?.resolve_handle(handle, now).await
    }

    pub async fn resolve_account(
        &self,
        store: &SealedStore,
        account_id: &AccountId,
        now: u64,
    ) -> Result<
        PrincipalRegistryEvidenceResolution<T::Error>,
        PrincipalRegistryEvidenceError<T::Error>,
    > {
        let _operation = self.operation.lock().await;
        self.open(store)?.resolve_account(account_id, now).await
    }

    pub async fn cached_public_key(
        &self,
        store: &SealedStore,
        public_key: &[u8; 32],
        now: u64,
    ) -> Result<PrincipalRegistryCacheLookup, PrincipalRegistryEvidenceError<T::Error>> {
        let _operation = self.operation.lock().await;
        Ok(self.open(store)?.cached_public_key(public_key, now))
    }

    pub async fn cached_handle(
        &self,
        store: &SealedStore,
        handle: &GlobalHandle,
        now: u64,
    ) -> Result<PrincipalRegistryCacheLookup, PrincipalRegistryEvidenceError<T::Error>> {
        let _operation = self.operation.lock().await;
        Ok(self.open(store)?.cached_handle(handle, now))
    }

    pub async fn cached_account(
        &self,
        store: &SealedStore,
        account_id: &AccountId,
        now: u64,
    ) -> Result<PrincipalRegistryCacheLookup, PrincipalRegistryEvidenceError<T::Error>> {
        let _operation = self.operation.lock().await;
        Ok(self.open(store)?.cached_account(account_id, now))
    }

    fn open<'store>(
        &self,
        store: &'store SealedStore,
    ) -> Result<PrincipalRegistryEvidenceClient<'store, T>, PrincipalRegistryEvidenceError<T::Error>>
    {
        PrincipalRegistryEvidenceClient::open(
            self.transport.clone(),
            store,
            self.pinned_public_key,
            self.max_age_seconds,
        )
    }
}
