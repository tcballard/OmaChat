use std::error::Error;
use std::fmt;

use crate::dm_relay_routing::{DmRelayRoute, DmRelayRouteProvenance};
use crate::event::{EventLimits, SignedEvent};
use crate::gift_wrap::GIFT_WRAP_KIND;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RoutedDmPublishPlan {
    event: SignedEvent,
    recipient_public_key: [u8; 32],
    relay_urls: Vec<String>,
    provenance: DmRelayRouteProvenance,
    required_acknowledgements: usize,
}

impl RoutedDmPublishPlan {
    pub fn event(&self) -> &SignedEvent {
        &self.event
    }

    pub fn into_event(self) -> SignedEvent {
        self.event
    }

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

pub fn plan_routed_dm_publish(
    event: SignedEvent,
    route: DmRelayRoute,
    now: u64,
    event_limits: &EventLimits,
) -> Result<RoutedDmPublishPlan, RoutedDmPublishError> {
    event
        .verify(now, event_limits)
        .map_err(|error| RoutedDmPublishError::InvalidEvent(error.to_string()))?;
    if event.kind != GIFT_WRAP_KIND {
        return Err(RoutedDmPublishError::WrongKind);
    }
    let recipient = hex::encode(route.recipient_public_key());
    let recipient_tags = event
        .tags
        .iter()
        .filter(|tag| tag.first().map(String::as_str) == Some("p"))
        .collect::<Vec<_>>();
    if recipient_tags.len() != 1
        || recipient_tags[0].len() != 2
        || recipient_tags[0].get(1).map(String::as_str) != Some(recipient.as_str())
    {
        return Err(RoutedDmPublishError::RecipientMismatch);
    }
    if route.relay_urls().is_empty() || route.required_acknowledgements() == 0 {
        return Err(RoutedDmPublishError::EmptyRoute);
    }

    Ok(RoutedDmPublishPlan {
        recipient_public_key: *route.recipient_public_key(),
        relay_urls: route.relay_urls().to_vec(),
        provenance: route.provenance().clone(),
        required_acknowledgements: route.required_acknowledgements(),
        event,
    })
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum RoutedDmPublishError {
    InvalidEvent(String),
    WrongKind,
    RecipientMismatch,
    EmptyRoute,
}

impl fmt::Display for RoutedDmPublishError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidEvent(error) => write!(formatter, "invalid routed DM event: {error}"),
            Self::WrongKind => formatter.write_str("routed DM publication requires kind 1059"),
            Self::RecipientMismatch => {
                formatter.write_str("gift-wrap recipient does not match the relay route")
            }
            Self::EmptyRoute => formatter.write_str("routed DM publication has no relay quorum"),
        }
    }
}

impl Error for RoutedDmPublishError {}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dm_relay_cache::VerifiedDmRelayCache;
    use crate::dm_relay_routing::{DmRelayRouteProvenance, DmRelayRoutingPolicy, route_dm_relays};
    use crate::event::{UnsignedEvent, xonly_public_key};

    const NOW: u64 = 1_800_000_000;

    fn gift_wrap(recipient: &[u8; 32]) -> SignedEvent {
        let wrapper_secret = [101; 32];
        UnsignedEvent::new(
            hex::encode(xonly_public_key(&wrapper_secret).expect("wrapper public key")),
            NOW,
            GIFT_WRAP_KIND,
            vec![vec!["p".into(), hex::encode(recipient)]],
            "opaque gift wrap".into(),
            &EventLimits::default(),
        )
        .expect("gift wrap")
        .sign_with_aux(&wrapper_secret, &[19; 32], &EventLimits::default())
        .expect("signed gift wrap")
    }

    fn route(recipient: &[u8; 32]) -> DmRelayRoute {
        route_dm_relays(
            &VerifiedDmRelayCache::new(),
            recipient,
            NOW,
            &["wss://bootstrap.example".into()],
            DmRelayRoutingPolicy {
                allow_bootstrap_when_missing: true,
                ..DmRelayRoutingPolicy::default()
            },
        )
        .expect("bootstrap route")
    }

    #[test]
    fn exact_recipient_event_and_route_become_one_immutable_plan() {
        let recipient = xonly_public_key(&[102; 32]).expect("recipient public key");
        let event = gift_wrap(&recipient);
        let plan = plan_routed_dm_publish(
            event.clone(),
            route(&recipient),
            NOW,
            &EventLimits::default(),
        )
        .expect("routed plan");
        assert_eq!(plan.event(), &event);
        assert_eq!(plan.recipient_public_key(), &recipient);
        assert_eq!(plan.relay_urls(), &["wss://bootstrap.example/"]);
        assert_eq!(
            plan.provenance(),
            &DmRelayRouteProvenance::BootstrapMissingMetadata
        );
        assert_eq!(plan.required_acknowledgements(), 1);
    }

    #[test]
    fn cross_recipient_and_tampered_events_fail_before_publication() {
        let recipient = xonly_public_key(&[103; 32]).expect("recipient public key");
        let other_recipient = xonly_public_key(&[104; 32]).expect("other recipient public key");
        assert_eq!(
            plan_routed_dm_publish(
                gift_wrap(&other_recipient),
                route(&recipient),
                NOW,
                &EventLimits::default(),
            ),
            Err(RoutedDmPublishError::RecipientMismatch)
        );

        let mut tampered = gift_wrap(&recipient);
        tampered.content.push('!');
        assert!(matches!(
            plan_routed_dm_publish(tampered, route(&recipient), NOW, &EventLimits::default(),),
            Err(RoutedDmPublishError::InvalidEvent(_))
        ));
    }
}
