use omachat_nostr::{
    discovery::NIP17_DM_RELAY_LIST_KIND,
    dm_relay_cache::{CacheMutation, DmRelayCacheLookup, VerifiedDmRelayCache},
    event::{EventLimits, SignedEvent, UnsignedEvent, xonly_public_key},
    inbox::{DmInboxError, DmInboxPolicy, verify_dm_inbox},
};

const NOW: u64 = 1_800_000_000;

fn signed_relay_list(secret_key: &[u8; 32], created_at: u64) -> SignedEvent {
    UnsignedEvent::new(
        hex::encode(xonly_public_key(secret_key).expect("valid public key")),
        created_at,
        NIP17_DM_RELAY_LIST_KIND,
        vec![vec!["relay".into(), "wss://recipient.example".into()]],
        String::new(),
        &EventLimits::default(),
    )
    .expect("valid relay list")
    .sign_with_aux(secret_key, &[7; 32], &EventLimits::default())
    .expect("signed relay list")
}

#[test]
fn only_recipient_authenticated_metadata_can_enter_the_cache() {
    let recipient_secret = [21; 32];
    let recipient = xonly_public_key(&recipient_secret).expect("recipient public key");
    let signed = signed_relay_list(&recipient_secret, NOW - 60);
    let verified = verify_dm_inbox(
        &signed,
        &recipient,
        NOW,
        &EventLimits::default(),
        &DmInboxPolicy::default(),
    )
    .expect("recipient-authenticated metadata");
    let record = verified
        .to_cache_record(NOW)
        .expect("verified metadata converts to cache record");
    let mut cache = VerifiedDmRelayCache::new();
    assert_eq!(cache.insert(record), Ok(CacheMutation::Stored));
    let DmRelayCacheLookup::Fresh(cached) = cache.lookup(
        &recipient,
        NOW,
        DmInboxPolicy::default().maximum_age_seconds,
    ) else {
        panic!("verified recipient relay list was not fresh");
    };
    assert_eq!(hex::encode(cached.source_event_id()), signed.id);
    assert_eq!(cached.relays(), &["wss://recipient.example/"]);

    let attacker_signed = signed_relay_list(&[22; 32], NOW - 30);
    assert_eq!(
        verify_dm_inbox(
            &attacker_signed,
            &recipient,
            NOW,
            &EventLimits::default(),
            &DmInboxPolicy::default(),
        ),
        Err(DmInboxError::RelayListSubjectMismatch)
    );
}
