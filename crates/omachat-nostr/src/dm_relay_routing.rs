use std::collections::BTreeSet;
use std::error::Error;
use std::fmt;

use k256::schnorr::VerifyingKey as SchnorrVerifyingKey;
use url::Url;

use crate::dm_relay_cache::{
    DmRelayCacheLookup, MAX_DM_RELAY_ENDPOINT_BYTES, MAX_DM_RELAYS_PER_RECIPIENT,
    VerifiedDmRelayCache, VerifiedDmRelayRecord,
};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DmRelayRoutingPolicy {
    pub freshness_window_seconds: u64,
    pub allow_stale_offline: bool,
    pub allow_bootstrap_when_missing: bool,
}

impl Default for DmRelayRoutingPolicy {
    fn default() -> Self {
        Self {
            freshness_window_seconds: 30 * 24 * 60 * 60,
            allow_stale_offline: false,
            allow_bootstrap_when_missing: false,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DmRelayRoute {
    recipient_public_key: [u8; 32],
    relay_urls: Vec<String>,
    provenance: DmRelayRouteProvenance,
    required_acknowledgements: usize,
}

impl DmRelayRoute {
    pub fn recipient_public_key(&self) -> &[u8; 32] {
        &self.recipient_public_key
    }

    pub fn relay_urls(&self) -> &[String] {
        &self.relay_urls
    }

    pub fn provenance(&self) -> &DmRelayRouteProvenance {
        &self.provenance
    }

    pub fn required_acknowledgements(&self) -> usize {
        self.required_acknowledgements
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum DmRelayRouteProvenance {
    VerifiedFresh { source_event_id: [u8; 32] },
    VerifiedOfflineStale { source_event_id: [u8; 32] },
    BootstrapMissingMetadata,
}

pub fn route_dm_relays(
    cache: &VerifiedDmRelayCache,
    recipient_pubkey: &[u8; 32],
    now: u64,
    bootstrap_relays: &[String],
    policy: DmRelayRoutingPolicy,
) -> Result<DmRelayRoute, DmRelayRoutingError> {
    SchnorrVerifyingKey::from_bytes(recipient_pubkey)
        .map_err(|_| DmRelayRoutingError::InvalidRecipientPublicKey)?;

    match cache.lookup(recipient_pubkey, now, policy.freshness_window_seconds) {
        DmRelayCacheLookup::Fresh(record) => route_verified(record, false),
        DmRelayCacheLookup::OfflineStale(record) if policy.allow_stale_offline => {
            route_verified(record, true)
        }
        DmRelayCacheLookup::OfflineStale(_) => Err(DmRelayRoutingError::StaleMetadata),
        DmRelayCacheLookup::UnusableClockRollback(_) => Err(DmRelayRoutingError::ClockRollback),
        DmRelayCacheLookup::Missing if policy.allow_bootstrap_when_missing => {
            route_bootstrap(recipient_pubkey, bootstrap_relays)
        }
        DmRelayCacheLookup::Missing => Err(DmRelayRoutingError::MissingMetadata),
    }
}

fn route_verified(
    record: &VerifiedDmRelayRecord,
    stale: bool,
) -> Result<DmRelayRoute, DmRelayRoutingError> {
    if record.relays().is_empty() {
        return Err(DmRelayRoutingError::NoRelayEndpoints);
    }
    let provenance = if stale {
        DmRelayRouteProvenance::VerifiedOfflineStale {
            source_event_id: *record.source_event_id(),
        }
    } else {
        DmRelayRouteProvenance::VerifiedFresh {
            source_event_id: *record.source_event_id(),
        }
    };
    Ok(route(
        *record.recipient_pubkey(),
        record.relays().to_vec(),
        provenance,
    ))
}

fn route_bootstrap(
    recipient_public_key: &[u8; 32],
    bootstrap_relays: &[String],
) -> Result<DmRelayRoute, DmRelayRoutingError> {
    if bootstrap_relays.is_empty() {
        return Err(DmRelayRoutingError::NoRelayEndpoints);
    }
    if bootstrap_relays.len() > MAX_DM_RELAYS_PER_RECIPIENT {
        return Err(DmRelayRoutingError::TooManyRelayEndpoints);
    }

    let mut canonical = Vec::with_capacity(bootstrap_relays.len());
    let mut seen = BTreeSet::new();
    for endpoint in bootstrap_relays {
        if endpoint.len() > MAX_DM_RELAY_ENDPOINT_BYTES {
            return Err(DmRelayRoutingError::RelayEndpointTooLong);
        }
        let parsed = Url::parse(endpoint).map_err(|_| DmRelayRoutingError::InvalidRelayEndpoint)?;
        if parsed.scheme() != "wss"
            || parsed.host_str().is_none()
            || !parsed.username().is_empty()
            || parsed.password().is_some()
            || parsed.fragment().is_some()
        {
            return Err(DmRelayRoutingError::InvalidRelayEndpoint);
        }
        let endpoint = parsed.to_string();
        if !seen.insert(endpoint.clone()) {
            return Err(DmRelayRoutingError::DuplicateRelayEndpoint);
        }
        canonical.push(endpoint);
    }
    canonical.sort();
    Ok(route(
        *recipient_public_key,
        canonical,
        DmRelayRouteProvenance::BootstrapMissingMetadata,
    ))
}

fn route(
    recipient_public_key: [u8; 32],
    relay_urls: Vec<String>,
    provenance: DmRelayRouteProvenance,
) -> DmRelayRoute {
    DmRelayRoute {
        recipient_public_key,
        required_acknowledgements: relay_urls.len().min(2),
        relay_urls,
        provenance,
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DmRelayRoutingError {
    InvalidRecipientPublicKey,
    MissingMetadata,
    StaleMetadata,
    ClockRollback,
    NoRelayEndpoints,
    TooManyRelayEndpoints,
    RelayEndpointTooLong,
    InvalidRelayEndpoint,
    DuplicateRelayEndpoint,
}

impl fmt::Display for DmRelayRoutingError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::InvalidRecipientPublicKey => "recipient public key is not a valid x-only key",
            Self::MissingMetadata => "recipient has no verified DM relay metadata",
            Self::StaleMetadata => "recipient DM relay metadata is stale",
            Self::ClockRollback => "local time precedes recipient DM relay metadata",
            Self::NoRelayEndpoints => "no DM relay endpoints are available",
            Self::TooManyRelayEndpoints => "too many DM relay endpoints",
            Self::RelayEndpointTooLong => "DM relay endpoint exceeds the configured bound",
            Self::InvalidRelayEndpoint => "invalid or insecure DM relay endpoint",
            Self::DuplicateRelayEndpoint => "duplicate DM relay endpoint",
        })
    }
}

impl Error for DmRelayRoutingError {}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::discovery::NIP17_DM_RELAY_LIST_KIND;
    use crate::event::{EventLimits, UnsignedEvent, xonly_public_key};
    use crate::inbox::{DmInboxPolicy, verify_dm_inbox};

    const NOW: u64 = 1_800_000_000;

    fn cache(
        created_at: u64,
        verified_at: u64,
        relays: &[&str],
    ) -> ([u8; 32], VerifiedDmRelayCache) {
        let secret = [41; 32];
        let recipient = xonly_public_key(&secret).expect("recipient public key");
        let event = UnsignedEvent::new(
            hex::encode(recipient),
            created_at,
            NIP17_DM_RELAY_LIST_KIND,
            relays
                .iter()
                .map(|relay| vec!["relay".to_owned(), (*relay).to_owned()])
                .collect(),
            String::new(),
            &EventLimits::default(),
        )
        .expect("relay list")
        .sign_with_aux(&secret, &[9; 32], &EventLimits::default())
        .expect("signed relay list");
        let verified = verify_dm_inbox(
            &event,
            &recipient,
            verified_at,
            &EventLimits::default(),
            &DmInboxPolicy::default(),
        )
        .expect("verified relay list");
        let mut cache = VerifiedDmRelayCache::new();
        cache
            .insert(verified.to_cache_record(verified_at).expect("cache record"))
            .expect("cache insert");
        (recipient, cache)
    }

    #[test]
    fn fresh_verified_route_never_mixes_in_bootstrap_relays() {
        let (recipient, cache) = cache(NOW - 60, NOW, &["wss://recipient.example"]);
        let route = route_dm_relays(
            &cache,
            &recipient,
            NOW,
            &["wss://bootstrap.example".into()],
            DmRelayRoutingPolicy {
                allow_bootstrap_when_missing: true,
                ..DmRelayRoutingPolicy::default()
            },
        )
        .expect("verified route");
        assert_eq!(route.relay_urls(), &["wss://recipient.example/"]);
        assert_eq!(route.recipient_public_key(), &recipient);
        assert!(matches!(
            route.provenance(),
            DmRelayRouteProvenance::VerifiedFresh { .. }
        ));
        assert_eq!(route.required_acknowledgements(), 1);
    }

    #[test]
    fn bootstrap_fallback_is_explicit_and_only_for_missing_metadata() {
        let cache = VerifiedDmRelayCache::new();
        let recipient = xonly_public_key(&[42; 32]).expect("recipient public key");
        assert_eq!(
            route_dm_relays(
                &cache,
                &recipient,
                NOW,
                &["wss://bootstrap.example".into()],
                DmRelayRoutingPolicy::default(),
            ),
            Err(DmRelayRoutingError::MissingMetadata)
        );
        let route = route_dm_relays(
            &cache,
            &recipient,
            NOW,
            &["wss://two.example".into(), "wss://one.example".into()],
            DmRelayRoutingPolicy {
                allow_bootstrap_when_missing: true,
                ..DmRelayRoutingPolicy::default()
            },
        )
        .expect("explicit bootstrap route");
        assert_eq!(
            route.relay_urls(),
            &["wss://one.example/", "wss://two.example/"]
        );
        assert_eq!(
            route.provenance(),
            &DmRelayRouteProvenance::BootstrapMissingMetadata
        );
        assert_eq!(route.recipient_public_key(), &recipient);
        assert_eq!(route.required_acknowledgements(), 2);
    }

    #[test]
    fn invalid_recipient_public_key_is_rejected_before_routing() {
        assert_eq!(
            route_dm_relays(
                &VerifiedDmRelayCache::new(),
                &[u8::MAX; 32],
                NOW,
                &["wss://bootstrap.example".into()],
                DmRelayRoutingPolicy {
                    allow_bootstrap_when_missing: true,
                    ..DmRelayRoutingPolicy::default()
                },
            ),
            Err(DmRelayRoutingError::InvalidRecipientPublicKey)
        );
    }

    #[test]
    fn stale_or_clock_rollback_state_never_falls_through_to_bootstrap() {
        let created_at = NOW - DmRelayRoutingPolicy::default().freshness_window_seconds - 1;
        let (recipient, cache) = cache(created_at, created_at + 1, &["wss://recipient.example"]);
        let bootstrap = ["wss://bootstrap.example".into()];
        let fallback_enabled = DmRelayRoutingPolicy {
            allow_bootstrap_when_missing: true,
            ..DmRelayRoutingPolicy::default()
        };
        assert_eq!(
            route_dm_relays(&cache, &recipient, NOW, &bootstrap, fallback_enabled),
            Err(DmRelayRoutingError::StaleMetadata)
        );

        let offline_route = route_dm_relays(
            &cache,
            &recipient,
            NOW,
            &bootstrap,
            DmRelayRoutingPolicy {
                allow_stale_offline: true,
                ..fallback_enabled
            },
        )
        .expect("explicit offline route");
        assert_eq!(offline_route.relay_urls(), &["wss://recipient.example/"]);
        assert!(matches!(
            offline_route.provenance(),
            DmRelayRouteProvenance::VerifiedOfflineStale { .. }
        ));
        assert_eq!(
            route_dm_relays(
                &cache,
                &recipient,
                created_at - 1,
                &bootstrap,
                fallback_enabled,
            ),
            Err(DmRelayRoutingError::ClockRollback)
        );
    }
}
