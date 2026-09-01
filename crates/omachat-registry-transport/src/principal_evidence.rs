use crate::{
    PrincipalRegistryClient, PrincipalRegistryClientError, RegistryTransport,
    VerifiedPrincipalRegistryRecord,
};
use omachat_crypto::{AccountId, GlobalHandle};
use omachat_registry::proof_bearing_claim::ProofBearingDeviceHandleClaim;
use omachat_store::{
    PrincipalRegistryCacheError, PrincipalRegistryCacheLookup, PrincipalRegistryEvidence,
    SealedStore, VerifiedPrincipalRegistryCache,
};
use std::{error::Error, fmt};

/// Online result or explicit transport-outage fallback for proven principals.
#[derive(Debug)]
pub enum PrincipalRegistryEvidenceResolution<E> {
    Online(PrincipalRegistryCacheLookup),
    Offline {
        cached: PrincipalRegistryCacheLookup,
        transport_error: E,
    },
}

impl<E> PrincipalRegistryEvidenceResolution<E> {
    #[must_use]
    pub const fn lookup(&self) -> &PrincipalRegistryCacheLookup {
        match self {
            Self::Online(lookup) | Self::Offline { cached: lookup, .. } => lookup,
        }
    }

    #[must_use]
    pub const fn is_online(&self) -> bool {
        matches!(self, Self::Online(_))
    }
}

/// Couples verified principal transport evidence to sealed explicit-offline state.
pub struct PrincipalRegistryEvidenceClient<'store, T> {
    client: PrincipalRegistryClient<T>,
    store: &'store SealedStore,
    cache: VerifiedPrincipalRegistryCache,
    max_age_seconds: u64,
}

impl<'store, T: RegistryTransport> PrincipalRegistryEvidenceClient<'store, T> {
    pub fn open(
        transport: T,
        store: &'store SealedStore,
        pinned_registry_key: [u8; 32],
        max_age_seconds: u64,
    ) -> Result<Self, PrincipalRegistryEvidenceError<T::Error>> {
        let cache = VerifiedPrincipalRegistryCache::load_or_create(store, pinned_registry_key)
            .map_err(PrincipalRegistryEvidenceError::Cache)?;
        Ok(Self {
            client: PrincipalRegistryClient::new(transport, pinned_registry_key),
            store,
            cache,
            max_age_seconds,
        })
    }

    /// Submit one idempotent proof-bearing claim and seal both verified
    /// receipts before reporting success. Transport failure leaves the
    /// mutation outcome unknown, so callers must retry the exact same claim.
    pub async fn claim_device(
        &mut self,
        claim: &ProofBearingDeviceHandleClaim,
        now: u64,
    ) -> Result<PrincipalRegistryCacheLookup, PrincipalRegistryEvidenceError<T::Error>> {
        let verified = match self.client.claim_device(claim).await {
            Ok(verified) => verified,
            Err(PrincipalRegistryClientError::Transport(error)) => {
                return Err(PrincipalRegistryEvidenceError::ClaimOutcomeUnknown(error));
            }
            Err(error) => return Err(PrincipalRegistryEvidenceError::Client(error)),
        };
        let account_id = verified.claim_receipt().account_id.clone();
        self.observe(verified, now)?;
        Ok(self
            .cache
            .lookup_account(&account_id, now, self.max_age_seconds))
    }

    pub async fn resolve_public_key(
        &mut self,
        public_key: &[u8; 32],
        now: u64,
    ) -> Result<
        PrincipalRegistryEvidenceResolution<T::Error>,
        PrincipalRegistryEvidenceError<T::Error>,
    > {
        match self.client.lookup_public_key(public_key).await {
            Ok(Some(verified)) => {
                self.observe(verified, now)?;
                Ok(PrincipalRegistryEvidenceResolution::Online(
                    self.cache
                        .lookup_public_key(public_key, now, self.max_age_seconds),
                ))
            }
            Ok(None) => self.online_missing(self.cache.lookup_public_key(
                public_key,
                now,
                self.max_age_seconds,
            )),
            Err(PrincipalRegistryClientError::Transport(transport_error)) => {
                Ok(PrincipalRegistryEvidenceResolution::Offline {
                    cached: self
                        .cache
                        .lookup_public_key(public_key, now, self.max_age_seconds),
                    transport_error,
                })
            }
            Err(error) => Err(PrincipalRegistryEvidenceError::Client(error)),
        }
    }

    pub async fn resolve_handle(
        &mut self,
        handle: &GlobalHandle,
        now: u64,
    ) -> Result<
        PrincipalRegistryEvidenceResolution<T::Error>,
        PrincipalRegistryEvidenceError<T::Error>,
    > {
        match self.client.lookup_handle(handle).await {
            Ok(Some(verified)) => {
                self.observe(verified, now)?;
                Ok(PrincipalRegistryEvidenceResolution::Online(
                    self.cache.lookup_handle(handle, now, self.max_age_seconds),
                ))
            }
            Ok(None) => {
                self.online_missing(self.cache.lookup_handle(handle, now, self.max_age_seconds))
            }
            Err(PrincipalRegistryClientError::Transport(transport_error)) => {
                Ok(PrincipalRegistryEvidenceResolution::Offline {
                    cached: self.cache.lookup_handle(handle, now, self.max_age_seconds),
                    transport_error,
                })
            }
            Err(error) => Err(PrincipalRegistryEvidenceError::Client(error)),
        }
    }

    pub async fn resolve_account(
        &mut self,
        account_id: &AccountId,
        now: u64,
    ) -> Result<
        PrincipalRegistryEvidenceResolution<T::Error>,
        PrincipalRegistryEvidenceError<T::Error>,
    > {
        match self.client.lookup_account(account_id).await {
            Ok(Some(verified)) => {
                self.observe(verified, now)?;
                Ok(PrincipalRegistryEvidenceResolution::Online(
                    self.cache
                        .lookup_account(account_id, now, self.max_age_seconds),
                ))
            }
            Ok(None) => self.online_missing(self.cache.lookup_account(
                account_id,
                now,
                self.max_age_seconds,
            )),
            Err(PrincipalRegistryClientError::Transport(transport_error)) => {
                Ok(PrincipalRegistryEvidenceResolution::Offline {
                    cached: self
                        .cache
                        .lookup_account(account_id, now, self.max_age_seconds),
                    transport_error,
                })
            }
            Err(error) => Err(PrincipalRegistryEvidenceError::Client(error)),
        }
    }

    #[must_use]
    pub fn cached_public_key(
        &self,
        public_key: &[u8; 32],
        now: u64,
    ) -> PrincipalRegistryCacheLookup {
        self.cache
            .lookup_public_key(public_key, now, self.max_age_seconds)
    }

    #[must_use]
    pub fn cached_handle(&self, handle: &GlobalHandle, now: u64) -> PrincipalRegistryCacheLookup {
        self.cache.lookup_handle(handle, now, self.max_age_seconds)
    }

    #[must_use]
    pub fn cached_account(&self, account_id: &AccountId, now: u64) -> PrincipalRegistryCacheLookup {
        self.cache
            .lookup_account(account_id, now, self.max_age_seconds)
    }

    #[must_use]
    pub const fn cache(&self) -> &VerifiedPrincipalRegistryCache {
        &self.cache
    }

    #[must_use]
    pub fn into_transport(self) -> T {
        self.client.into_transport()
    }

    fn observe(
        &mut self,
        verified: VerifiedPrincipalRegistryRecord,
        now: u64,
    ) -> Result<(), PrincipalRegistryEvidenceError<T::Error>> {
        self.cache
            .observe(
                self.store,
                PrincipalRegistryEvidence {
                    claim: verified.claim().clone(),
                    claim_receipt: verified.claim_receipt().clone(),
                    principal_receipt: verified.principal_receipt().clone(),
                },
                now,
            )
            .map_err(PrincipalRegistryEvidenceError::Cache)
    }

    fn online_missing(
        &self,
        cached: PrincipalRegistryCacheLookup,
    ) -> Result<
        PrincipalRegistryEvidenceResolution<T::Error>,
        PrincipalRegistryEvidenceError<T::Error>,
    > {
        if cached.record().is_some() {
            Err(PrincipalRegistryEvidenceError::AuthoritativeRollback)
        } else {
            Ok(PrincipalRegistryEvidenceResolution::Online(
                PrincipalRegistryCacheLookup::Missing,
            ))
        }
    }
}

#[derive(Debug)]
pub enum PrincipalRegistryEvidenceError<E> {
    Client(PrincipalRegistryClientError<E>),
    Cache(PrincipalRegistryCacheError),
    ClaimOutcomeUnknown(E),
    AuthoritativeRollback,
}

impl<E: fmt::Display> fmt::Display for PrincipalRegistryEvidenceError<E> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Client(error) => error.fmt(formatter),
            Self::Cache(error) => error.fmt(formatter),
            Self::ClaimOutcomeUnknown(error) => write!(
                formatter,
                "principal registry claim outcome is unknown after transport failure: {error}"
            ),
            Self::AuthoritativeRollback => formatter.write_str(
                "principal registry returned not-found for previously verified cached evidence",
            ),
        }
    }
}

impl<E: Error + 'static> Error for PrincipalRegistryEvidenceError<E> {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Client(error) => Some(error),
            Self::Cache(error) => Some(error),
            Self::ClaimOutcomeUnknown(error) => Some(error),
            Self::AuthoritativeRollback => None,
        }
    }
}
