//! Fail-closed NIP-17 inbox verification and publication planning.

use crate::{
    discovery::{RelayDiscoveryLimits, parse_nip17_dm_relay_list},
    event::{EventLimits, SignedEvent},
    gift_wrap::GIFT_WRAP_KIND,
};
use std::{error::Error, fmt};

/// Product policy for using recipient-authored kind 10050 inbox metadata.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DmInboxPolicy {
    pub maximum_age_seconds: u64,
    pub max_relays: usize,
    pub max_url_bytes: usize,
    pub require_tls: bool,
}

impl Default for DmInboxPolicy {
    fn default() -> Self {
        Self {
            maximum_age_seconds: 30 * 24 * 60 * 60,
            max_relays: 3,
            max_url_bytes: 2_048,
            require_tls: true,
        }
    }
}

/// Signature-verified and policy-checked recipient inbox metadata.
///
/// Fields are intentionally private so a publication plan cannot be created
/// from relay URLs that bypassed kind 10050 signature and subject checks.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct VerifiedDmInbox {
    recipient_public_key: String,
    source_event_id: String,
    source_created_at: u64,
    relay_urls: Vec<String>,
}

impl VerifiedDmInbox {
    #[must_use]
    pub fn recipient_public_key(&self) -> &str {
        &self.recipient_public_key
    }

    #[must_use]
    pub fn source_event_id(&self) -> &str {
        &self.source_event_id
    }

    #[must_use]
    pub const fn source_created_at(&self) -> u64 {
        self.source_created_at
    }

    #[must_use]
    pub fn relay_urls(&self) -> &[String] {
        &self.relay_urls
    }
}

/// Immutable send intent. Callers must create connections only for `relay_urls`;
/// there is deliberately no default/bootstrap relay fallback.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DmPublishPlan {
    pub event: SignedEvent,
    pub recipient_public_key: String,
    pub relay_urls: Vec<String>,
    pub required_acknowledgements: usize,
    pub inbox_event_id: String,
}

/// Authenticate and constrain one recipient's replaceable kind 10050 event.
pub fn verify_dm_inbox(
    event: &SignedEvent,
    expected_recipient_public_key: &[u8; 32],
    now: u64,
    event_limits: &EventLimits,
    policy: &DmInboxPolicy,
) -> Result<VerifiedDmInbox, DmInboxError> {
    validate_policy(policy)?;
    let expected_recipient = hex::encode(expected_recipient_public_key);
    let discovery_limits = RelayDiscoveryLimits {
        max_relays: policy.max_relays,
        max_url_bytes: policy.max_url_bytes,
    };
    let list = parse_nip17_dm_relay_list(event, now, event_limits, &discovery_limits)
        .map_err(|error| DmInboxError::InvalidRelayList(error.to_string()))?;
    if list.public_key != expected_recipient {
        return Err(DmInboxError::RelayListSubjectMismatch);
    }
    if list.created_at > now {
        return Err(DmInboxError::RelayListFromFuture);
    }
    let age = now - list.created_at;
    if age > policy.maximum_age_seconds {
        return Err(DmInboxError::StaleRelayList {
            age_seconds: age,
            maximum_seconds: policy.maximum_age_seconds,
        });
    }
    let relay_urls = list
        .relays
        .into_iter()
        .map(|relay| relay.url)
        .collect::<Vec<_>>();
    if policy.require_tls && relay_urls.iter().any(|relay| !relay.starts_with("wss://")) {
        return Err(DmInboxError::InsecureRelay);
    }
    Ok(VerifiedDmInbox {
        recipient_public_key: expected_recipient,
        source_event_id: event.id.clone(),
        source_created_at: list.created_at,
        relay_urls,
    })
}

/// Bind one persistent NIP-59 gift wrap to its verified recipient inbox.
pub fn plan_dm_publish(
    gift_wrap: SignedEvent,
    inbox: &VerifiedDmInbox,
    now: u64,
    event_limits: &EventLimits,
) -> Result<DmPublishPlan, DmInboxError> {
    gift_wrap
        .verify(now, event_limits)
        .map_err(|error| DmInboxError::InvalidGiftWrap(error.to_string()))?;
    if gift_wrap.kind != GIFT_WRAP_KIND {
        return Err(DmInboxError::WrongGiftWrapKind);
    }
    let recipient_tags = gift_wrap
        .tags
        .iter()
        .filter(|tag| tag.first().map(String::as_str) == Some("p"))
        .collect::<Vec<_>>();
    if recipient_tags.len() != 1
        || recipient_tags[0].get(1).map(String::as_str) != Some(inbox.recipient_public_key.as_str())
    {
        return Err(DmInboxError::GiftWrapRecipientMismatch);
    }
    let required_acknowledgements = inbox.relay_urls.len().min(2);
    if required_acknowledgements == 0 {
        return Err(DmInboxError::InvalidPolicy);
    }
    Ok(DmPublishPlan {
        event: gift_wrap,
        recipient_public_key: inbox.recipient_public_key.clone(),
        relay_urls: inbox.relay_urls.clone(),
        required_acknowledgements,
        inbox_event_id: inbox.source_event_id.clone(),
    })
}

fn validate_policy(policy: &DmInboxPolicy) -> Result<(), DmInboxError> {
    if policy.maximum_age_seconds == 0
        || policy.max_relays == 0
        || policy.max_relays > 3
        || policy.max_url_bytes == 0
    {
        return Err(DmInboxError::InvalidPolicy);
    }
    Ok(())
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum DmInboxError {
    InvalidPolicy,
    InvalidRelayList(String),
    RelayListSubjectMismatch,
    RelayListFromFuture,
    StaleRelayList {
        age_seconds: u64,
        maximum_seconds: u64,
    },
    InsecureRelay,
    InvalidGiftWrap(String),
    WrongGiftWrapKind,
    GiftWrapRecipientMismatch,
}

impl fmt::Display for DmInboxError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidPolicy => formatter.write_str("invalid DM inbox policy"),
            Self::InvalidRelayList(error) => write!(formatter, "invalid kind 10050 event: {error}"),
            Self::RelayListSubjectMismatch => {
                formatter.write_str("kind 10050 author does not match the intended recipient")
            }
            Self::RelayListFromFuture => {
                formatter.write_str("kind 10050 event is dated in the future")
            }
            Self::StaleRelayList {
                age_seconds,
                maximum_seconds,
            } => write!(
                formatter,
                "kind 10050 event age {age_seconds}s exceeds {maximum_seconds}s"
            ),
            Self::InsecureRelay => formatter.write_str("DM inbox policy requires wss relay URLs"),
            Self::InvalidGiftWrap(error) => write!(formatter, "invalid gift wrap: {error}"),
            Self::WrongGiftWrapKind => {
                formatter.write_str("offline DM publication requires persistent kind 1059")
            }
            Self::GiftWrapRecipientMismatch => {
                formatter.write_str("gift-wrap recipient does not match the verified inbox owner")
            }
        }
    }
}

impl Error for DmInboxError {}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        event::{UnsignedEvent, xonly_public_key},
        gift_wrap::{
            ChatRecipient, GiftWrapMaterial, GiftWrapPersistence, create_chat_rumor,
            create_gift_wrap_with_material,
        },
    };

    const NOW: u64 = 1_800_000_000;

    fn relay_list(secret: &[u8; 32], created_at: u64, relays: &[&str]) -> SignedEvent {
        let public_key = hex::encode(xonly_public_key(secret).unwrap());
        UnsignedEvent::new(
            public_key,
            created_at,
            crate::discovery::NIP17_DM_RELAY_LIST_KIND,
            relays
                .iter()
                .map(|relay| vec!["relay".to_owned(), (*relay).to_owned()])
                .collect(),
            String::new(),
            &EventLimits::default(),
        )
        .unwrap()
        .sign_with_aux(secret, &[7; 32], &EventLimits::default())
        .unwrap()
    }

    fn gift_wrap(
        sender: &[u8; 32],
        recipient_secret: &[u8; 32],
        persistence: GiftWrapPersistence,
    ) -> SignedEvent {
        let recipient = xonly_public_key(recipient_secret).unwrap();
        let limits = EventLimits::default();
        let rumor = create_chat_rumor(
            sender,
            NOW,
            &[ChatRecipient {
                public_key: recipient,
                relay_hint: None,
            }],
            "hello".to_owned(),
            None,
            None,
            &limits,
        )
        .unwrap();
        create_gift_wrap_with_material(
            &rumor,
            sender,
            &recipient,
            persistence,
            GiftWrapMaterial {
                seal_created_at: NOW - 10,
                seal_nonce: [1; 32],
                seal_auxiliary_randomness: [2; 32],
                wrapper_secret_key: [3; 32],
                wrapper_created_at: NOW - 20,
                wrapper_nonce: [4; 32],
                wrapper_auxiliary_randomness: [5; 32],
            },
            &limits,
        )
        .unwrap()
    }

    #[test]
    fn plans_only_verified_recipient_relays_with_a_bounded_quorum() {
        let sender = [1; 32];
        let recipient_secret = [2; 32];
        let recipient = xonly_public_key(&recipient_secret).unwrap();
        let list = relay_list(
            &recipient_secret,
            NOW - 60,
            &[
                "wss://one.example",
                "wss://two.example",
                "wss://one.example/",
            ],
        );
        let inbox = verify_dm_inbox(
            &list,
            &recipient,
            NOW,
            &EventLimits::default(),
            &DmInboxPolicy::default(),
        )
        .unwrap();
        let plan = plan_dm_publish(
            gift_wrap(&sender, &recipient_secret, GiftWrapPersistence::Persistent),
            &inbox,
            NOW,
            &EventLimits::default(),
        )
        .unwrap();
        assert_eq!(
            plan.relay_urls,
            vec!["wss://one.example/", "wss://two.example/"]
        );
        assert_eq!(plan.required_acknowledgements, 2);
        assert_eq!(plan.inbox_event_id, list.id);
    }

    #[test]
    fn rejects_forged_mismatched_stale_future_and_insecure_lists() {
        let recipient_secret = [2; 32];
        let recipient = xonly_public_key(&recipient_secret).unwrap();
        let limits = EventLimits::default();
        let policy = DmInboxPolicy::default();

        let mut forged = relay_list(&recipient_secret, NOW - 1, &["wss://one.example"]);
        forged.tags[0][1] = "wss://attacker.example".to_owned();
        assert!(verify_dm_inbox(&forged, &recipient, NOW, &limits, &policy).is_err());

        let other = relay_list(&[8; 32], NOW - 1, &["wss://one.example"]);
        assert_eq!(
            verify_dm_inbox(&other, &recipient, NOW, &limits, &policy).unwrap_err(),
            DmInboxError::RelayListSubjectMismatch
        );

        let stale = relay_list(
            &recipient_secret,
            NOW - policy.maximum_age_seconds - 1,
            &["wss://one.example"],
        );
        assert!(matches!(
            verify_dm_inbox(&stale, &recipient, NOW, &limits, &policy),
            Err(DmInboxError::StaleRelayList { .. })
        ));

        let future = relay_list(&recipient_secret, NOW + 1, &["wss://one.example"]);
        assert_eq!(
            verify_dm_inbox(&future, &recipient, NOW, &limits, &policy).unwrap_err(),
            DmInboxError::RelayListFromFuture
        );

        let insecure = relay_list(&recipient_secret, NOW - 1, &["ws://localhost:8080"]);
        assert_eq!(
            verify_dm_inbox(&insecure, &recipient, NOW, &limits, &policy).unwrap_err(),
            DmInboxError::InsecureRelay
        );
    }

    #[test]
    fn refuses_wrong_recipient_and_ephemeral_fallback() {
        let sender = [1; 32];
        let recipient_secret = [2; 32];
        let recipient = xonly_public_key(&recipient_secret).unwrap();
        let inbox = verify_dm_inbox(
            &relay_list(&recipient_secret, NOW - 1, &["wss://only.example"]),
            &recipient,
            NOW,
            &EventLimits::default(),
            &DmInboxPolicy::default(),
        )
        .unwrap();
        let wrong = gift_wrap(&sender, &[8; 32], GiftWrapPersistence::Persistent);
        assert_eq!(
            plan_dm_publish(wrong, &inbox, NOW, &EventLimits::default()).unwrap_err(),
            DmInboxError::GiftWrapRecipientMismatch
        );

        let ephemeral = gift_wrap(&sender, &recipient_secret, GiftWrapPersistence::Ephemeral);
        assert_eq!(
            plan_dm_publish(ephemeral, &inbox, NOW, &EventLimits::default()).unwrap_err(),
            DmInboxError::WrongGiftWrapKind
        );
    }
}
