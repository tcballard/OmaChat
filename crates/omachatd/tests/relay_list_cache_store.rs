use std::fs;

use omachat_nostr::{
    discovery::{RelayDiscoveryLimits, RelayPreference},
    event::{EventLimits, SignedEvent, xonly_public_key},
    relay_list::create_nip65_relay_list_with_aux,
    relay_list_cache::{
        DEFAULT_RELAY_LIST_FRESHNESS_SECONDS, RelayListCacheLookup, RelayListCacheMutation,
        VerifiedRelayListCache,
    },
};
use omachat_store::{RequestedProvider, SealedStore, StoreError};
use omachatd::{
    NIP65_RELAY_LIST_CACHE_RECORD_NAME, SealedRelayListCache, SealedRelayListCacheError,
    SealedRelayListCacheState,
};
use tempfile::tempdir;

const NOW: u64 = 1_800_000_000;

fn relay_event(secret: [u8; 32], created_at: u64, url: &str) -> ([u8; 32], SignedEvent) {
    let public_key = xonly_public_key(&secret).expect("public key");
    let event = create_nip65_relay_list_with_aux(
        &secret,
        created_at,
        &[RelayPreference {
            url: url.into(),
            read: true,
            write: true,
        }],
        &[18; 32],
        &EventLimits::default(),
        &RelayDiscoveryLimits::default(),
    )
    .expect("signed relay list");
    (public_key, event)
}

fn relay_cache(created_at: u64) -> ([u8; 32], VerifiedRelayListCache) {
    let (public_key, event) = relay_event([111; 32], created_at, "wss://external.example");
    let mut cache = VerifiedRelayListCache::new();
    cache
        .insert_event(
            event,
            NOW,
            NOW,
            &EventLimits::default(),
            &RelayDiscoveryLimits::default(),
        )
        .expect("cache relay list");
    (public_key, cache)
}

#[tokio::test]
async fn verified_relay_list_is_durable_before_mutation_is_exposed() {
    let directory = tempdir().expect("state directory");
    let (public_key, event) = relay_event([112; 32], NOW - 1, "wss://portable.example");
    let store = SealedStore::open(directory.path(), RequestedProvider::File)
        .await
        .expect("open store");
    assert_eq!(
        SealedRelayListCache::new(&store)
            .verify_and_save(
                &event,
                &public_key,
                NOW,
                &EventLimits::default(),
                &RelayDiscoveryLimits::default(),
            )
            .expect("verify and save"),
        RelayListCacheMutation::Stored
    );
    drop(store);

    let reopened = SealedStore::open(directory.path(), RequestedProvider::File)
        .await
        .expect("reopen store");
    let SealedRelayListCacheState::Loaded(cache) = SealedRelayListCache::new(&reopened)
        .load(
            NOW,
            &EventLimits::default(),
            &RelayDiscoveryLimits::default(),
        )
        .expect("load relay list")
    else {
        panic!("stored relay list missing after restart");
    };
    let RelayListCacheLookup::Fresh(record) =
        cache.lookup(&public_key, NOW, DEFAULT_RELAY_LIST_FRESHNESS_SECONDS)
    else {
        panic!("stored relay list is not fresh");
    };
    assert_eq!(record.relay_list().relays[0].url, "wss://portable.example/");
}

#[tokio::test]
async fn wrong_expected_author_never_creates_persisted_state() {
    let directory = tempdir().expect("state directory");
    let expected = xonly_public_key(&[113; 32]).expect("expected public key");
    let (_, forged) = relay_event([114; 32], NOW - 1, "wss://impostor.example");
    let store = SealedStore::open(directory.path(), RequestedProvider::File)
        .await
        .expect("open store");
    let adapter = SealedRelayListCache::new(&store);
    assert!(matches!(
        adapter.verify_and_save(
            &forged,
            &expected,
            NOW,
            &EventLimits::default(),
            &RelayDiscoveryLimits::default(),
        ),
        Err(SealedRelayListCacheError::UnexpectedAuthor)
    ));
    assert!(matches!(
        adapter.load(
            NOW,
            &EventLimits::default(),
            &RelayDiscoveryLimits::default()
        ),
        Ok(SealedRelayListCacheState::Missing)
    ));
}

#[tokio::test]
async fn sealed_cache_survives_restart_without_refreshing_stale_data() {
    let directory = tempdir().expect("state directory");
    let created_at = NOW - DEFAULT_RELAY_LIST_FRESHNESS_SECONDS - 1;
    let (public_key, cache) = relay_cache(created_at);
    let store = SealedStore::open(directory.path(), RequestedProvider::File)
        .await
        .expect("open store");
    SealedRelayListCache::new(&store)
        .save(&cache)
        .expect("save cache");
    drop(store);

    let reopened = SealedStore::open(directory.path(), RequestedProvider::File)
        .await
        .expect("reopen store");
    let SealedRelayListCacheState::Loaded(loaded) = SealedRelayListCache::new(&reopened)
        .load(
            NOW,
            &EventLimits::default(),
            &RelayDiscoveryLimits::default(),
        )
        .expect("load cache")
    else {
        panic!("relay-list cache was missing after restart");
    };
    assert!(matches!(
        loaded.lookup(&public_key, NOW, DEFAULT_RELAY_LIST_FRESHNESS_SECONDS),
        RelayListCacheLookup::OfflineStale(_)
    ));
}

#[tokio::test]
async fn ciphertext_and_signed_relay_list_tampering_fail_closed() {
    let directory = tempdir().expect("state directory");
    let (_, cache) = relay_cache(NOW - 60);
    let store = SealedStore::open(directory.path(), RequestedProvider::File)
        .await
        .expect("open store");
    let adapter = SealedRelayListCache::new(&store);
    adapter.save(&cache).expect("save cache");

    let record_path = directory
        .path()
        .join("records")
        .join(NIP65_RELAY_LIST_CACHE_RECORD_NAME);
    let mut ciphertext = fs::read(&record_path).expect("read ciphertext");
    *ciphertext.last_mut().expect("non-empty ciphertext") ^= 1;
    fs::write(&record_path, ciphertext).expect("tamper ciphertext");
    assert!(matches!(
        adapter.load(
            NOW,
            &EventLimits::default(),
            &RelayDiscoveryLimits::default()
        ),
        Err(SealedRelayListCacheError::Store(StoreError::Authentication))
    ));

    let encoded = cache.to_json().expect("cache JSON");
    let tampered = String::from_utf8(encoded)
        .expect("UTF-8 JSON")
        .replace("external.example", "attacker.example");
    store
        .write(NIP65_RELAY_LIST_CACHE_RECORD_NAME, tampered.as_bytes())
        .expect("seal tampered relay list");
    assert!(matches!(
        adapter.load(
            NOW,
            &EventLimits::default(),
            &RelayDiscoveryLimits::default()
        ),
        Err(SealedRelayListCacheError::Cache(_))
    ));
}

#[tokio::test]
async fn clear_returns_an_explicit_missing_state() {
    let directory = tempdir().expect("state directory");
    let (_, cache) = relay_cache(NOW - 60);
    let store = SealedStore::open(directory.path(), RequestedProvider::File)
        .await
        .expect("open store");
    let adapter = SealedRelayListCache::new(&store);
    adapter.save(&cache).expect("save cache");
    adapter.clear().expect("clear cache");
    assert!(matches!(
        adapter.load(
            NOW,
            &EventLimits::default(),
            &RelayDiscoveryLimits::default()
        ),
        Ok(SealedRelayListCacheState::Missing)
    ));
}
