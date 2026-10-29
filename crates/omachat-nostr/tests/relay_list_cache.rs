use omachat_nostr::{
    discovery::{RelayDiscoveryLimits, RelayPreference},
    event::{EventLimits, SignedEvent, xonly_public_key},
    relay_list::create_nip65_relay_list_with_aux,
    relay_list_cache::{
        RelayListCacheError, RelayListCacheLookup, RelayListCacheMutation, VerifiedRelayListCache,
    },
};

const NOW: u64 = 1_800_000_000;

fn relay_list(secret: [u8; 32], created_at: u64, url: &str, auxiliary: u8) -> SignedEvent {
    create_nip65_relay_list_with_aux(
        &secret,
        created_at,
        &[RelayPreference {
            url: url.into(),
            read: true,
            write: true,
        }],
        &[auxiliary; 32],
        &EventLimits::default(),
        &RelayDiscoveryLimits::default(),
    )
    .expect("signed relay list")
}

fn insert(
    cache: &mut VerifiedRelayListCache,
    event: SignedEvent,
) -> Result<RelayListCacheMutation, RelayListCacheError> {
    cache.insert_event(
        event,
        NOW,
        NOW,
        &EventLimits::default(),
        &RelayDiscoveryLimits::default(),
    )
}

#[test]
fn freshness_offline_state_and_clock_rollback_are_explicit() {
    let secret = [91; 32];
    let public_key = xonly_public_key(&secret).expect("public key");
    let mut cache = VerifiedRelayListCache::new();
    assert_eq!(
        insert(
            &mut cache,
            relay_list(secret, NOW - 10, "wss://relay.example", 92)
        ),
        Ok(RelayListCacheMutation::Stored)
    );
    assert!(matches!(
        cache.lookup(&public_key, NOW, 10),
        RelayListCacheLookup::Fresh(_)
    ));
    assert!(matches!(
        cache.lookup(&public_key, NOW + 1, 10),
        RelayListCacheLookup::OfflineStale(_)
    ));
    assert!(matches!(
        cache.lookup(&public_key, NOW - 11, 10),
        RelayListCacheLookup::UnusableClockRollback(_)
    ));
}

#[test]
fn rollback_fails_closed_and_same_timestamp_uses_the_nip01_lowest_id() {
    let secret = [93; 32];
    let current = relay_list(secret, NOW - 10, "wss://current.example", 94);
    let alternative = relay_list(secret, NOW - 10, "wss://conflict.example", 96);
    let (lowest, highest) = if current.id < alternative.id {
        (current, alternative)
    } else {
        (alternative, current)
    };
    let public_key = xonly_public_key(&secret).expect("public key");
    let mut cache = VerifiedRelayListCache::new();
    assert_eq!(
        insert(&mut cache, highest.clone()),
        Ok(RelayListCacheMutation::Stored)
    );
    assert_eq!(
        insert(&mut cache, lowest.clone()),
        Ok(RelayListCacheMutation::Stored)
    );
    assert_eq!(
        insert(
            &mut cache,
            relay_list(secret, NOW - 11, "wss://older.example", 95)
        ),
        Err(RelayListCacheError::Rollback)
    );
    assert_eq!(
        insert(&mut cache, highest),
        Ok(RelayListCacheMutation::Unchanged)
    );
    let RelayListCacheLookup::Fresh(selected) = cache.lookup(&public_key, NOW, 10) else {
        panic!("selected relay list must remain fresh");
    };
    assert_eq!(selected.source_event().id, lowest.id);
}

#[test]
fn persisted_events_are_reverified_and_remain_bound_to_the_nostr_key() {
    let secret = [97; 32];
    let public_key = xonly_public_key(&secret).expect("public key");
    let mut cache = VerifiedRelayListCache::new();
    insert(
        &mut cache,
        relay_list(secret, NOW - 10, "wss://external.example", 98),
    )
    .expect("insert relay list");
    let encoded = cache.to_json().expect("cache JSON");
    let restored = VerifiedRelayListCache::from_json(
        &encoded,
        NOW,
        &EventLimits::default(),
        &RelayDiscoveryLimits::default(),
    )
    .expect("validated restart");
    assert_eq!(restored, cache);
    let RelayListCacheLookup::Fresh(record) = restored.lookup(&public_key, NOW, 10) else {
        panic!("restored relay list was not fresh");
    };
    assert_eq!(record.relay_list().public_key, hex::encode(public_key));
    assert_eq!(
        record.relay_list().relays,
        vec![RelayPreference {
            url: "wss://external.example/".into(),
            read: true,
            write: true,
        }]
    );

    let tampered = String::from_utf8(encoded)
        .expect("UTF-8 JSON")
        .replace("external.example", "attacker.example");
    assert_eq!(
        VerifiedRelayListCache::from_json(
            tampered.as_bytes(),
            NOW,
            &EventLimits::default(),
            &RelayDiscoveryLimits::default(),
        ),
        Err(RelayListCacheError::InvalidSourceEvent)
    );
}

#[test]
fn relay_origin_cannot_make_a_forged_list_cacheable() {
    let secret = [99; 32];
    let mut forged = relay_list(secret, NOW - 1, "wss://valid.example", 100);
    forged.tags[0][1] = "wss://forged.example/".into();
    assert_eq!(
        insert(&mut VerifiedRelayListCache::new(), forged),
        Err(RelayListCacheError::InvalidSourceEvent)
    );
}
