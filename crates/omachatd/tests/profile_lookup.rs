use omachat_nostr::{
    event::{EventLimits, UnsignedEvent, xonly_public_key},
    profile_cache::DEFAULT_PROFILE_FRESHNESS_SECONDS,
    profile_metadata::PROFILE_METADATA_KIND,
};
use omachat_proto::ipc::{Command, Request, ResponseOutcome, VERSION};
use omachat_store::{RequestedProvider, SealedStore};
use omachatd::{
    DaemonConfig, DaemonCore, EventHub, RequestHandler, SealedProfileCache, StorageProviderConfig,
};
use serde_json::{Value, json};
use tempfile::tempdir;

#[tokio::test]
async fn cached_profile_reports_explicit_offline_and_missing_states() {
    let state = tempdir().unwrap();
    let participant_secret = [121; 32];
    let participant = xonly_public_key(&participant_secret).unwrap();
    let now = unix_now();
    let event = UnsignedEvent::new(
        hex::encode(participant),
        now - DEFAULT_PROFILE_FRESHNESS_SECONDS - 1,
        PROFILE_METADATA_KIND,
        Vec::new(),
        json!({"name": "offline-agent", "display_name": "Offline Agent"}).to_string(),
        &EventLimits::default(),
    )
    .unwrap()
    .sign_with_aux(&participant_secret, &[122; 32], &EventLimits::default())
    .unwrap();
    let store = SealedStore::open(state.path(), RequestedProvider::File)
        .await
        .unwrap();
    SealedProfileCache::new(&store)
        .verify_and_save(&event, &participant, now, &EventLimits::default())
        .unwrap();
    drop(store);

    let core = DaemonCore::open(
        state.path(),
        DaemonConfig {
            storage_provider: StorageProviderConfig::File,
            ..DaemonConfig::default()
        },
        EventHub::default(),
    )
    .await
    .unwrap();
    let cached = command(&core, hex::encode(participant)).await;
    assert_eq!(cached["cache_status"], "offline-stale");
    assert_eq!(cached["nostr_name"], "offline-agent");
    assert_eq!(cached["display_name"], "Offline Agent");
    assert_eq!(cached["global_handle_verified"], false);

    let missing = xonly_public_key(&[123; 32]).unwrap();
    let missing = command(&core, hex::encode(missing)).await;
    assert_eq!(missing["cache_status"], "missing");
    assert_eq!(missing["global_handle_verified"], false);
}

fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

async fn command(core: &DaemonCore, public_key: String) -> Value {
    match core
        .handle(Request {
            version: VERSION,
            id: "profile-cache".into(),
            command: Command::ShowProfile { public_key },
        })
        .await
    {
        ResponseOutcome::Ok { result } => result,
        ResponseOutcome::Error { error } => panic!("profile lookup failed: {}", error.message),
    }
}
use std::time::{SystemTime, UNIX_EPOCH};
