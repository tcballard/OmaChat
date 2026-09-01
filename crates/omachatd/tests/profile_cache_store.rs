use std::fs;

use omachat_nostr::{
    event::{EventLimits, SignedEvent, UnsignedEvent, xonly_public_key},
    profile_cache::{
        DEFAULT_PROFILE_FRESHNESS_SECONDS, ProfileCacheLookup, ProfileCacheMutation,
        VerifiedProfileCache,
    },
    profile_metadata::PROFILE_METADATA_KIND,
    profile_verification::verify_profile_metadata,
};
use omachat_store::{RequestedProvider, SealedStore, StoreError};
use omachatd::{
    PROFILE_CACHE_RECORD_NAME, SealedProfileCache, SealedProfileCacheError, SealedProfileCacheState,
};
use tempfile::tempdir;

const NOW: u64 = 1_800_000_000;

fn profile_event(secret: [u8; 32], created_at: u64, display_name: &str) -> ([u8; 32], SignedEvent) {
    let public_key = xonly_public_key(&secret).expect("public key");
    let event = UnsignedEvent::new(
        hex::encode(public_key),
        created_at,
        PROFILE_METADATA_KIND,
        Vec::new(),
        format!(r#"{{"name":"external","display_name":"{display_name}"}}"#),
        &EventLimits::default(),
    )
    .expect("profile event")
    .sign_with_aux(&secret, &[18; 32], &EventLimits::default())
    .expect("signed profile");
    (public_key, event)
}

fn profile_cache(created_at: u64) -> ([u8; 32], VerifiedProfileCache) {
    let (public_key, event) = profile_event([91; 32], created_at, "External User");
    let profile = verify_profile_metadata(&event, &public_key, NOW, &EventLimits::default())
        .expect("verified profile");
    let mut cache = VerifiedProfileCache::new();
    cache.insert(profile, NOW).expect("cache profile");
    (public_key, cache)
}

#[tokio::test]
async fn verified_profile_is_durable_before_the_mutation_is_exposed() {
    let directory = tempdir().expect("state directory");
    let (public_key, event) = profile_event([92; 32], NOW - 1, "Portable Agent");
    let store = SealedStore::open(directory.path(), RequestedProvider::File)
        .await
        .expect("open store");
    assert_eq!(
        SealedProfileCache::new(&store)
            .verify_and_save(&event, &public_key, NOW, &EventLimits::default())
            .expect("verify and save"),
        ProfileCacheMutation::Stored
    );
    drop(store);

    let reopened = SealedStore::open(directory.path(), RequestedProvider::File)
        .await
        .expect("reopen store");
    let SealedProfileCacheState::Loaded(cache) = SealedProfileCache::new(&reopened)
        .load(NOW, &EventLimits::default())
        .expect("load profile")
    else {
        panic!("stored profile missing after restart");
    };
    let ProfileCacheLookup::Fresh(record) =
        cache.lookup(&public_key, NOW, DEFAULT_PROFILE_FRESHNESS_SECONDS)
    else {
        panic!("stored profile is not fresh");
    };
    assert_eq!(record.profile().display_name(), Some("Portable Agent"));
}

#[tokio::test]
async fn forged_profile_authorship_never_creates_persisted_state() {
    let directory = tempdir().expect("state directory");
    let expected = xonly_public_key(&[93; 32]).expect("expected public key");
    let (_, forged) = profile_event([94; 32], NOW - 1, "Impostor");
    let store = SealedStore::open(directory.path(), RequestedProvider::File)
        .await
        .expect("open store");
    let adapter = SealedProfileCache::new(&store);
    assert!(matches!(
        adapter.verify_and_save(&forged, &expected, NOW, &EventLimits::default()),
        Err(SealedProfileCacheError::Verification(_))
    ));
    assert!(matches!(
        adapter.load(NOW, &EventLimits::default()),
        Ok(SealedProfileCacheState::Missing)
    ));
}

#[tokio::test]
async fn sealed_profile_cache_survives_restart_without_refreshing_stale_data() {
    let directory = tempdir().expect("state directory");
    let created_at = NOW - DEFAULT_PROFILE_FRESHNESS_SECONDS - 1;
    let (public_key, cache) = profile_cache(created_at);
    let store = SealedStore::open(directory.path(), RequestedProvider::File)
        .await
        .expect("open store");
    SealedProfileCache::new(&store)
        .save(&cache)
        .expect("save cache");
    drop(store);

    let reopened = SealedStore::open(directory.path(), RequestedProvider::File)
        .await
        .expect("reopen store");
    let SealedProfileCacheState::Loaded(loaded) = SealedProfileCache::new(&reopened)
        .load(NOW, &EventLimits::default())
        .expect("load cache")
    else {
        panic!("profile cache was missing after restart");
    };
    assert!(matches!(
        loaded.lookup(&public_key, NOW, DEFAULT_PROFILE_FRESHNESS_SECONDS),
        ProfileCacheLookup::OfflineStale(_)
    ));
}

#[tokio::test]
async fn ciphertext_and_signed_profile_tampering_fail_closed() {
    let directory = tempdir().expect("state directory");
    let (_, cache) = profile_cache(NOW - 60);
    let store = SealedStore::open(directory.path(), RequestedProvider::File)
        .await
        .expect("open store");
    let adapter = SealedProfileCache::new(&store);
    adapter.save(&cache).expect("save cache");

    let record_path = directory
        .path()
        .join("records")
        .join(PROFILE_CACHE_RECORD_NAME);
    let mut ciphertext = fs::read(&record_path).expect("read ciphertext");
    *ciphertext.last_mut().expect("non-empty ciphertext") ^= 1;
    fs::write(&record_path, ciphertext).expect("tamper ciphertext");
    assert!(matches!(
        adapter.load(NOW, &EventLimits::default()),
        Err(SealedProfileCacheError::Store(StoreError::Authentication))
    ));

    let encoded = cache.to_json().expect("cache JSON");
    let tampered = String::from_utf8(encoded)
        .expect("UTF-8 JSON")
        .replace("External User", "Attacker");
    store
        .write(PROFILE_CACHE_RECORD_NAME, tampered.as_bytes())
        .expect("seal tampered profile");
    assert!(matches!(
        adapter.load(NOW, &EventLimits::default()),
        Err(SealedProfileCacheError::Cache(_))
    ));
}

#[tokio::test]
async fn clear_returns_an_explicit_missing_state() {
    let directory = tempdir().expect("state directory");
    let (_, cache) = profile_cache(NOW - 60);
    let store = SealedStore::open(directory.path(), RequestedProvider::File)
        .await
        .expect("open store");
    let adapter = SealedProfileCache::new(&store);
    adapter.save(&cache).expect("save cache");
    adapter.clear().expect("clear cache");
    assert!(matches!(
        adapter.load(NOW, &EventLimits::default()),
        Ok(SealedProfileCacheState::Missing)
    ));
}
