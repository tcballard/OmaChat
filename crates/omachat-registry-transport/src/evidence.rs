use crate::{RegistryClient, RegistryClientError, RegistryTransport};
use omachat_crypto::{AccountId, GlobalHandle};
use omachat_store::{RegistryCacheError, RegistryCacheLookup, SealedStore, VerifiedRegistryCache};
use std::{error::Error, fmt};

/// Result of resolving registry state with explicit online/offline provenance.
#[derive(Debug)]
pub enum RegistryEvidenceResolution<E> {
    Online(RegistryCacheLookup),
    Offline {
        cached: RegistryCacheLookup,
        transport_error: E,
    },
}

impl<E> RegistryEvidenceResolution<E> {
    #[must_use]
    pub const fn lookup(&self) -> &RegistryCacheLookup {
        match self {
            Self::Online(lookup) | Self::Offline { cached: lookup, .. } => lookup,
        }
    }

    #[must_use]
    pub const fn is_online(&self) -> bool {
        matches!(self, Self::Online(_))
    }
}

/// Couples the verified registry transport client to sealed rollback-aware
/// evidence without embedding any deployment or endpoint policy.
pub struct RegistryEvidenceClient<'store, T> {
    client: RegistryClient<T>,
    store: &'store SealedStore,
    cache: VerifiedRegistryCache,
    max_age_seconds: u64,
}

impl<'store, T: RegistryTransport> RegistryEvidenceClient<'store, T> {
    pub fn open(
        transport: T,
        store: &'store SealedStore,
        pinned_registry_key: [u8; 32],
        max_age_seconds: u64,
    ) -> Result<Self, RegistryEvidenceError<T::Error>> {
        let cache = VerifiedRegistryCache::load_or_create(store, pinned_registry_key)
            .map_err(RegistryEvidenceError::Cache)?;
        Ok(Self {
            client: RegistryClient::new(transport, pinned_registry_key),
            store,
            cache,
            max_age_seconds,
        })
    }

    /// Resolve a handle online. Only a transport outage permits explicit cached
    /// fallback; protocol, correlation, query, and signature failures remain
    /// terminal. A live `not found` cannot erase previously observed ownership.
    pub async fn resolve_handle(
        &mut self,
        handle: &GlobalHandle,
        now: u64,
    ) -> Result<RegistryEvidenceResolution<T::Error>, RegistryEvidenceError<T::Error>> {
        match self.client.lookup_handle(handle).await {
            Ok(Some(record)) => {
                self.cache
                    .observe(self.store, record, now)
                    .map_err(RegistryEvidenceError::Cache)?;
                Ok(RegistryEvidenceResolution::Online(
                    self.cache.lookup_handle(handle, now, self.max_age_seconds),
                ))
            }
            Ok(None) => {
                let cached = self.cache.lookup_handle(handle, now, self.max_age_seconds);
                if cached.record().is_some() {
                    Err(RegistryEvidenceError::AuthoritativeRollback)
                } else {
                    Ok(RegistryEvidenceResolution::Online(
                        RegistryCacheLookup::Missing,
                    ))
                }
            }
            Err(RegistryClientError::Transport(transport_error)) => {
                Ok(RegistryEvidenceResolution::Offline {
                    cached: self.cache.lookup_handle(handle, now, self.max_age_seconds),
                    transport_error,
                })
            }
            Err(error) => Err(RegistryEvidenceError::Client(error)),
        }
    }

    /// Resolve an account using the same fail-closed and explicit-offline rules
    /// as [`Self::resolve_handle`].
    pub async fn resolve_account(
        &mut self,
        account_id: &AccountId,
        now: u64,
    ) -> Result<RegistryEvidenceResolution<T::Error>, RegistryEvidenceError<T::Error>> {
        match self.client.lookup_account(account_id).await {
            Ok(Some(record)) => {
                self.cache
                    .observe(self.store, record, now)
                    .map_err(RegistryEvidenceError::Cache)?;
                Ok(RegistryEvidenceResolution::Online(
                    self.cache
                        .lookup_account(account_id, now, self.max_age_seconds),
                ))
            }
            Ok(None) => {
                let cached = self
                    .cache
                    .lookup_account(account_id, now, self.max_age_seconds);
                if cached.record().is_some() {
                    Err(RegistryEvidenceError::AuthoritativeRollback)
                } else {
                    Ok(RegistryEvidenceResolution::Online(
                        RegistryCacheLookup::Missing,
                    ))
                }
            }
            Err(RegistryClientError::Transport(transport_error)) => {
                Ok(RegistryEvidenceResolution::Offline {
                    cached: self
                        .cache
                        .lookup_account(account_id, now, self.max_age_seconds),
                    transport_error,
                })
            }
            Err(error) => Err(RegistryEvidenceError::Client(error)),
        }
    }

    #[must_use]
    pub fn cached_handle(&self, handle: &GlobalHandle, now: u64) -> RegistryCacheLookup {
        self.cache.lookup_handle(handle, now, self.max_age_seconds)
    }

    #[must_use]
    pub fn cached_account(&self, account_id: &AccountId, now: u64) -> RegistryCacheLookup {
        self.cache
            .lookup_account(account_id, now, self.max_age_seconds)
    }

    #[must_use]
    pub fn cached_nostr_public_key(&self, public_key: &[u8; 32], now: u64) -> RegistryCacheLookup {
        self.cache
            .lookup_nostr_public_key(public_key, now, self.max_age_seconds)
    }

    #[must_use]
    pub const fn cache(&self) -> &VerifiedRegistryCache {
        &self.cache
    }

    pub fn into_transport(self) -> T {
        self.client.into_transport()
    }
}

#[derive(Debug)]
pub enum RegistryEvidenceError<E> {
    Client(RegistryClientError<E>),
    Cache(RegistryCacheError),
    AuthoritativeRollback,
}

impl<E: fmt::Display> fmt::Display for RegistryEvidenceError<E> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Client(error) => error.fmt(formatter),
            Self::Cache(error) => error.fmt(formatter),
            Self::AuthoritativeRollback => formatter
                .write_str("registry returned not-found for previously verified cached evidence"),
        }
    }
}

impl<E: Error + 'static> Error for RegistryEvidenceError<E> {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Client(error) => Some(error),
            Self::Cache(error) => Some(error),
            Self::AuthoritativeRollback => None,
        }
    }
}
