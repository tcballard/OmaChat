use std::fs;

use omachat_nostr::{
    discovery::NIP17_DM_RELAY_LIST_KIND,
    dm_relay_cache::{CacheMutation, DmRelayCacheLookup, VerifiedDmRelayCache},
    dm_relay_routing::{DmRelayRouteProvenance, DmRelayRoutingPolicy},
    event::{EventLimits, SignedEvent, UnsignedEvent, xonly_public_key},
    inbox::{DmInboxPolicy, verify_dm_inbox},
};
use omachat_store::{RequestedProvider, SealedStore, StoreError};
use omachatd::{
    DM_RELAY_CACHE_RECORD_NAME, SealedDmRelayCache, SealedDmRelayCacheError,
    SealedDmRelayCacheState,
};
use tempfile::tempdir;

const NOW: u64 = 1_800_000_000;

fn relay_list(secret: [u8; 32], created_at: u64, relay: &str) -> ([u8; 32], SignedEvent) {
    let recipient = xonly_public_key(&secret).expect("recipient public key");
    let event = UnsignedEvent::new(
        hex::encode(recipient),
        created_at,
        NIP17_DM_RELAY_LIST_KIND,
        vec![vec!["relay".into(), relay.into()]],
        String::new(),
        &EventLimits::default(),
    )
    .expect("relay list")
    .sign_with_aux(&secret, &[8; 32], &EventLimits::default())
    .expect("signed relay list");
    (recipient, event)
}

fn cache(created_at: u64, verified_at: u64) -> ([u8; 32], VerifiedDmRelayCache) {
    let (recipient, event) = relay_list([31; 32], created_at, "wss://recipient.example");
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

#[tokio::test]
async fn verified_metadata_is_durable_before_a_route_is_exposed() {
    let state = tempdir().expect("state directory");
    let (recipient, event) = relay_list([30; 32], NOW - 1, "wss://recipient.example");
    let store = SealedStore::open(state.path(), RequestedProvider::File)
        .await
        .expect("open store");
    assert_eq!(
        SealedDmRelayCache::new(&store)
            .verify_and_save(
                &event,
                &recipient,
                NOW,
                &EventLimits::default(),
                &DmInboxPolicy::default(),
            )
            .expect("verify and save"),
        CacheMutation::Stored
    );
    drop(store);

    let reopened = SealedStore::open(state.path(), RequestedProvider::File)
        .await
        .expect("reopen store");
    let route = SealedDmRelayCache::new(&reopened)
        .route(
            &recipient,
            NOW,
            &[],
            DmRelayRoutingPolicy::default(),
            &EventLimits::default(),
            &DmInboxPolicy::default(),
        )
        .expect("durable route");
    assert_eq!(route.recipient_public_key(), &recipient);
    assert_eq!(route.relay_urls(), &["wss://recipient.example/"]);
    assert!(matches!(
        route.provenance(),
        DmRelayRouteProvenance::VerifiedFresh { .. }
    ));
}

#[tokio::test]
async fn forged_recipient_metadata_never_creates_persisted_state() {
    let state = tempdir().expect("state directory");
    let expected_recipient = xonly_public_key(&[29; 32]).expect("expected recipient");
    let (_, attacker_event) = relay_list([28; 32], NOW - 1, "wss://attacker.example");
    let store = SealedStore::open(state.path(), RequestedProvider::File)
        .await
        .expect("open store");
    let adapter = SealedDmRelayCache::new(&store);
    assert!(matches!(
        adapter.verify_and_save(
            &attacker_event,
            &expected_recipient,
            NOW,
            &EventLimits::default(),
            &DmInboxPolicy::default(),
        ),
        Err(SealedDmRelayCacheError::Inbox(_))
    ));
    assert!(matches!(
        adapter.load(NOW, &EventLimits::default(), &DmInboxPolicy::default()),
        Ok(SealedDmRelayCacheState::Missing)
    ));
}

#[tokio::test]
async fn sealed_cache_survives_restart_without_claiming_stale_state_is_fresh() {
    let state = tempdir().expect("state directory");
    let created_at = NOW - DmInboxPolicy::default().maximum_age_seconds - 1;
    let verified_at = created_at + 1;
    let (recipient, cache) = cache(created_at, verified_at);

    let store = SealedStore::open(state.path(), RequestedProvider::File)
        .await
        .expect("open store");
    SealedDmRelayCache::new(&store)
        .save(&cache)
        .expect("save cache");
    drop(store);

    let reopened = SealedStore::open(state.path(), RequestedProvider::File)
        .await
        .expect("reopen store");
    let SealedDmRelayCacheState::Loaded(loaded) = SealedDmRelayCache::new(&reopened)
        .load(NOW, &EventLimits::default(), &DmInboxPolicy::default())
        .expect("load cache")
    else {
        panic!("sealed cache was missing after restart");
    };
    assert!(matches!(
        loaded.lookup(
            &recipient,
            NOW,
            DmInboxPolicy::default().maximum_age_seconds
        ),
        DmRelayCacheLookup::OfflineStale(_)
    ));
}

#[tokio::test]
async fn ciphertext_and_signed_source_tampering_fail_closed() {
    let state = tempdir().expect("state directory");
    let (_, cache) = cache(NOW - 60, NOW);
    let store = SealedStore::open(state.path(), RequestedProvider::File)
        .await
        .expect("open store");
    let adapter = SealedDmRelayCache::new(&store);
    adapter.save(&cache).expect("save cache");

    let record_path = state
        .path()
        .join("records")
        .join(DM_RELAY_CACHE_RECORD_NAME);
    let mut ciphertext = fs::read(&record_path).expect("read ciphertext");
    *ciphertext.last_mut().expect("non-empty ciphertext") ^= 1;
    fs::write(&record_path, ciphertext).expect("tamper ciphertext");
    assert!(matches!(
        adapter.load(NOW, &EventLimits::default(), &DmInboxPolicy::default()),
        Err(SealedDmRelayCacheError::Store(StoreError::Authentication))
    ));

    let encoded = cache.to_json().expect("cache JSON");
    let tampered = String::from_utf8(encoded)
        .expect("JSON text")
        .replace("wss://recipient.example", "wss://attacker.example");
    store
        .write(DM_RELAY_CACHE_RECORD_NAME, tampered.as_bytes())
        .expect("seal tampered source");
    assert!(matches!(
        adapter.load(NOW, &EventLimits::default(), &DmInboxPolicy::default()),
        Err(SealedDmRelayCacheError::Cache(_))
    ));
}

#[tokio::test]
async fn clear_returns_the_cache_to_an_explicit_missing_state() {
    let state = tempdir().expect("state directory");
    let (_, cache) = cache(NOW - 60, NOW);
    let store = SealedStore::open(state.path(), RequestedProvider::File)
        .await
        .expect("open store");
    let adapter = SealedDmRelayCache::new(&store);
    adapter.save(&cache).expect("save cache");
    adapter.clear().expect("clear cache");
    assert!(matches!(
        adapter.load(NOW, &EventLimits::default(), &DmInboxPolicy::default()),
        Ok(SealedDmRelayCacheState::Missing)
    ));
}
