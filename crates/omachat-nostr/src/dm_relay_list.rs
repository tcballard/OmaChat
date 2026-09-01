use std::collections::BTreeSet;
use std::error::Error;
use std::fmt;

use url::Url;

use crate::discovery::NIP17_DM_RELAY_LIST_KIND;
use crate::dm_relay_cache::{MAX_DM_RELAY_ENDPOINT_BYTES, MAX_DM_RELAYS_PER_RECIPIENT};
use crate::event::{EventLimits, SignedEvent, UnsignedEvent, xonly_public_key};

pub fn create_dm_relay_list(
    secret_key: &[u8; 32],
    created_at: u64,
    relay_urls: &[String],
    event_limits: &EventLimits,
) -> Result<SignedEvent, DmRelayListError> {
    let mut auxiliary_randomness = [0; 32];
    getrandom::fill(&mut auxiliary_randomness).map_err(|_| DmRelayListError::Random)?;
    create_dm_relay_list_with_aux(
        secret_key,
        created_at,
        relay_urls,
        &auxiliary_randomness,
        event_limits,
    )
}

pub fn create_dm_relay_list_with_aux(
    secret_key: &[u8; 32],
    created_at: u64,
    relay_urls: &[String],
    auxiliary_randomness: &[u8; 32],
    event_limits: &EventLimits,
) -> Result<SignedEvent, DmRelayListError> {
    let relay_urls = canonical_relay_urls(relay_urls)?;
    let public_key = xonly_public_key(secret_key)
        .map_err(|error| DmRelayListError::InvalidKey(error.to_string()))?;
    let event = UnsignedEvent::new(
        hex::encode(public_key),
        created_at,
        NIP17_DM_RELAY_LIST_KIND,
        relay_urls
            .into_iter()
            .map(|relay| vec!["relay".to_owned(), relay])
            .collect(),
        String::new(),
        event_limits,
    )
    .map_err(|error| DmRelayListError::InvalidEvent(error.to_string()))?;
    event
        .sign_with_aux(secret_key, auxiliary_randomness, event_limits)
        .map_err(|error| DmRelayListError::InvalidEvent(error.to_string()))
}

fn canonical_relay_urls(relay_urls: &[String]) -> Result<Vec<String>, DmRelayListError> {
    if relay_urls.is_empty() {
        return Err(DmRelayListError::NoRelays);
    }
    if relay_urls.len() > MAX_DM_RELAYS_PER_RECIPIENT {
        return Err(DmRelayListError::TooManyRelays);
    }
    let mut canonical = Vec::with_capacity(relay_urls.len());
    let mut seen = BTreeSet::new();
    for endpoint in relay_urls {
        if endpoint.len() > MAX_DM_RELAY_ENDPOINT_BYTES {
            return Err(DmRelayListError::EndpointTooLong);
        }
        let parsed = Url::parse(endpoint).map_err(|_| DmRelayListError::InvalidEndpoint)?;
        if parsed.scheme() != "wss"
            || parsed.host_str().is_none()
            || !parsed.username().is_empty()
            || parsed.password().is_some()
            || parsed.fragment().is_some()
        {
            return Err(DmRelayListError::InvalidEndpoint);
        }
        let endpoint = parsed.to_string();
        if !seen.insert(endpoint.clone()) {
            return Err(DmRelayListError::DuplicateEndpoint);
        }
        canonical.push(endpoint);
    }
    canonical.sort();
    Ok(canonical)
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum DmRelayListError {
    Random,
    InvalidKey(String),
    InvalidEvent(String),
    InvalidEndpoint,
    EndpointTooLong,
    DuplicateEndpoint,
    NoRelays,
    TooManyRelays,
}

impl fmt::Display for DmRelayListError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Random => formatter.write_str("secure randomness unavailable"),
            Self::InvalidKey(error) => write!(formatter, "invalid Nostr key: {error}"),
            Self::InvalidEvent(error) => write!(formatter, "invalid DM relay-list event: {error}"),
            Self::InvalidEndpoint => formatter.write_str("invalid or insecure DM relay endpoint"),
            Self::EndpointTooLong => {
                formatter.write_str("DM relay endpoint exceeds the configured bound")
            }
            Self::DuplicateEndpoint => formatter.write_str("duplicate DM relay endpoint"),
            Self::NoRelays => formatter.write_str("DM relay list requires at least one endpoint"),
            Self::TooManyRelays => formatter.write_str("too many DM relay endpoints"),
        }
    }
}

impl Error for DmRelayListError {}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::inbox::{DmInboxPolicy, verify_dm_inbox};

    const NOW: u64 = 1_800_000_000;

    #[test]
    fn publishes_a_standard_recipient_authored_list_without_implicit_relays() {
        let secret = [51; 32];
        let recipient = xonly_public_key(&secret).expect("recipient public key");
        let event = create_dm_relay_list_with_aux(
            &secret,
            NOW,
            &["wss://two.example".into(), "wss://one.example/path".into()],
            &[10; 32],
            &EventLimits::default(),
        )
        .expect("signed relay list");
        assert_eq!(event.kind, NIP17_DM_RELAY_LIST_KIND);
        assert_eq!(event.pubkey, hex::encode(recipient));
        let verified = verify_dm_inbox(
            &event,
            &recipient,
            NOW,
            &EventLimits::default(),
            &DmInboxPolicy::default(),
        )
        .expect("standard verifier accepts event");
        assert_eq!(
            verified.relay_urls(),
            &["wss://one.example/path", "wss://two.example/"]
        );
        assert!(
            verified
                .relay_urls()
                .iter()
                .all(|relay| !relay.contains("omachat"))
        );
    }

    #[test]
    fn empty_list_is_rejected_before_signing() {
        let secret = [52; 32];
        assert_eq!(
            create_dm_relay_list_with_aux(&secret, NOW, &[], &[11; 32], &EventLimits::default(),),
            Err(DmRelayListError::NoRelays)
        );
    }

    #[test]
    fn insecure_duplicate_and_unbounded_lists_fail_before_signing() {
        let secret = [53; 32];
        assert_eq!(
            create_dm_relay_list_with_aux(
                &secret,
                NOW,
                &["ws://insecure.example".into()],
                &[12; 32],
                &EventLimits::default(),
            ),
            Err(DmRelayListError::InvalidEndpoint)
        );
        assert_eq!(
            create_dm_relay_list_with_aux(
                &secret,
                NOW,
                &["wss://same.example".into(), "wss://same.example/".into()],
                &[12; 32],
                &EventLimits::default(),
            ),
            Err(DmRelayListError::DuplicateEndpoint)
        );
        assert_eq!(
            create_dm_relay_list_with_aux(
                &secret,
                NOW,
                &[
                    "wss://one.example".into(),
                    "wss://two.example".into(),
                    "wss://three.example".into(),
                    "wss://four.example".into(),
                ],
                &[12; 32],
                &EventLimits::default(),
            ),
            Err(DmRelayListError::TooManyRelays)
        );
    }
}
