use omachat_nostr::{
    event::{EventLimits, SignedEvent, UnsignedEvent, xonly_public_key},
    nip11::{RelayInformation, RelayInformationLimits},
    nip29::{GroupMembershipAction, GroupMetadata, GroupRoster, GroupUserEvent, group_message},
    nip29_delete::{AcceptedGroupDeletion, GroupDeleteRequest, delete_event_request},
    nip29_lifecycle::{
        AcceptedLifecycleAction, GroupLifecycleRequest, GroupStatus, LifecycleApplyResult,
        create_group_request, create_invite_request, delete_group_request,
    },
    nip29_metadata::{AcceptedMetadataEdit, GroupMetadataEdit, MetadataApplyResult},
    nip29_pins::GroupPinList,
    nip29_room_state::{RelayRoomState, RoomStateError},
    nip29_state::MembershipApplyResult,
};
use omachat_store::{
    RequestedProvider, RoomStateAnchorError, RoomStateGenerationAnchor, RoomStateLoad,
    RoomStateVault, RoomStateVaultError, SealedStore, StoreError,
};
use std::{collections::BTreeMap, fs, sync::Mutex};
use tempfile::TempDir;

const NOW: u64 = 1_800_000_000;
const RELAY_SECRET: [u8; 32] = [5; 32];
const OTHER_RELAY_SECRET: [u8; 32] = [11; 32];
const MODERATOR_SECRET: [u8; 32] = [7; 32];
const AGENT_SECRET: [u8; 32] = [9; 32];
const CONTEXT: &str = "device:0123456789abcdef";

#[derive(Default)]
struct TestGenerationAnchor {
    generations: Mutex<BTreeMap<(String, String), u64>>,
}

impl TestGenerationAnchor {
    fn generation(&self, context: &str, relay: &str) -> Option<u64> {
        self.generations
            .lock()
            .expect("anchor lock")
            .get(&(context.to_owned(), relay.to_owned()))
            .copied()
    }

    fn set_unchecked(&self, context: &str, relay: &str, generation: u64) {
        self.generations
            .lock()
            .expect("anchor lock")
            .insert((context.to_owned(), relay.to_owned()), generation);
    }
}

impl RoomStateGenerationAnchor for TestGenerationAnchor {
    fn load_generation(
        &self,
        store_context: &str,
        relay_pubkey: &str,
    ) -> Result<Option<u64>, RoomStateAnchorError> {
        Ok(self.generation(store_context, relay_pubkey))
    }

    fn store_generation(
        &self,
        store_context: &str,
        relay_pubkey: &str,
        generation: u64,
    ) -> Result<(), RoomStateAnchorError> {
        let mut generations = self.generations.lock().expect("anchor lock");
        let key = (store_context.to_owned(), relay_pubkey.to_owned());
        if generations.get(&key).is_some_and(|current| *current > generation) {
            return Err(RoomStateAnchorError::new("generation cannot decrease"));
        }
        generations.insert(key, generation);
        Ok(())
    }
}

fn limits() -> EventLimits {
    EventLimits::default()
}

fn pubkey(secret: &[u8; 32]) -> String {
    hex::encode(xonly_public_key(secret).expect("key"))
}

fn tag(parts: &[&str]) -> Vec<String> {
    parts.iter().map(|part| (*part).to_owned()).collect()
}

fn sign(unsigned: UnsignedEvent, secret: &[u8; 32]) -> SignedEvent {
    unsigned
        .sign_with_aux(secret, &[3; 32], &limits())
        .expect("signed")
}

fn signed(secret: &[u8; 32], created_at: u64, kind: u32, tags: Vec<Vec<String>>) -> SignedEvent {
    sign(
        UnsignedEvent::new(
            pubkey(secret),
            created_at,
            kind,
            tags,
            String::new(),
            &limits(),
        )
        .expect("event"),
        secret,
    )
}

fn admins(relay: &[u8; 32], group: &str, admin: &str) -> GroupRoster {
    GroupRoster::verify(
        signed(
            relay,
            NOW - 100,
            39001,
            vec![tag(&["d", group]), tag(&["p", admin, "moderator"])],
        ),
        &pubkey(relay),
        NOW,
        &limits(),
    )
    .expect("roster")
}

/// A relay with two groups: one live and edited, one created then deleted.
fn build_state(relay_secret: &[u8; 32]) -> RelayRoomState {
    let relay = pubkey(relay_secret);
    let moderator = pubkey(&MODERATOR_SECRET);
    let mut state = RelayRoomState::new(relay.clone()).expect("state");

    let information = RelayInformation::from_json(
        format!(r#"{{"self":"{relay}","supported_nips":[29],"software":"grain"}}"#).as_bytes(),
        &RelayInformationLimits::default(),
    )
    .expect("information");
    state
        .identities_mut()
        .observe("wss://relay.example", &information, NOW - 500)
        .expect("bind");

    let roster = admins(relay_secret, "omarchy", &moderator);
    state.observe_roster(&roster).expect("roster");

    let metadata = GroupMetadata::verify(
        signed(
            relay_secret,
            NOW - 90,
            39000,
            vec![
                tag(&["d", "omarchy"]),
                tag(&["name", "Omarchy"]),
                tag(&["private"]),
            ],
        ),
        &relay,
        NOW,
        &limits(),
    )
    .expect("metadata");
    state
        .metadata_mut()
        .observe_snapshot(&metadata)
        .expect("snapshot");
    let edit = GroupMetadataEdit::verify(
        signed(
            &MODERATOR_SECRET,
            NOW - 80,
            9002,
            vec![
                tag(&["h", "omarchy"]),
                tag(&["about", "Linux talk"]),
                tag(&["public"]),
            ],
        ),
        NOW,
        &limits(),
    )
    .expect("edit");
    state
        .metadata_mut()
        .apply_accepted(
            &AcceptedMetadataEdit::from_authoritative_relay(edit, &relay).expect("accepted"),
        )
        .expect("edit applied");

    let creation = GroupLifecycleRequest::verify(
        sign(
            create_group_request(pubkey(&AGENT_SECRET), NOW - 70, "omarchy", &limits())
                .expect("create"),
            &AGENT_SECRET,
        ),
        NOW,
        &limits(),
    )
    .expect("creation");
    state
        .lifecycle_mut()
        .apply_accepted(
            &AcceptedLifecycleAction::from_authoritative_relay(creation, &relay)
                .expect("accepted"),
        )
        .expect("created");
    let invite = GroupLifecycleRequest::verify(
        sign(
            create_invite_request(moderator.clone(), NOW - 60, "omarchy", "welcome", &limits())
                .expect("invite"),
            &MODERATOR_SECRET,
        ),
        NOW,
        &limits(),
    )
    .expect("invite");
    state
        .lifecycle_mut()
        .apply_accepted(
            &AcceptedLifecycleAction::from_authoritative_relay(invite, &relay)
                .expect("accepted"),
        )
        .expect("invited");

    // A second group that gets created and then deleted.
    for request in [
        sign(
            create_group_request(moderator.clone(), NOW - 55, "closed", &limits()).expect("create"),
            &MODERATOR_SECRET,
        ),
        sign(
            delete_group_request(moderator.clone(), NOW - 50, "closed", &limits()).expect("delete"),
            &MODERATOR_SECRET,
        ),
    ] {
        let request = GroupLifecycleRequest::verify(request, NOW, &limits()).expect("request");
        state
            .lifecycle_mut()
            .apply_accepted(
                &AcceptedLifecycleAction::from_authoritative_relay(request, &relay)
                    .expect("accepted"),
            )
            .expect("applied");
    }

    let put = GroupMembershipAction::verify(
        signed(
            &MODERATOR_SECRET,
            NOW - 40,
            9000,
            vec![
                tag(&["h", "omarchy"]),
                tag(&["p", &pubkey(&AGENT_SECRET), "agent"]),
            ],
        ),
        NOW,
        &limits(),
    )
    .expect("put");
    state.apply_membership(&put).expect("membership");

    let message = GroupUserEvent::verify(
        sign(
            group_message(
                pubkey(&AGENT_SECRET),
                NOW - 30,
                "omarchy",
                "hello".to_owned(),
                &[],
                &limits(),
            )
            .expect("message"),
            &AGENT_SECRET,
        ),
        NOW,
        &limits(),
    )
    .expect("message");
    let deletion = GroupDeleteRequest::verify(
        sign(
            delete_event_request(
                pubkey(&AGENT_SECRET),
                NOW - 20,
                "omarchy",
                &[message.event().id.clone()],
                String::new(),
                &[],
                &limits(),
            )
            .expect("delete"),
            &AGENT_SECRET,
        ),
        NOW,
        &limits(),
    )
    .expect("deletion");
    state
        .apply_deletion(
            &AcceptedGroupDeletion::from_authoritative_relay(deletion, &relay)
            .expect("accepted"),
        )
        .expect("deleted");

    let pins = GroupPinList::verify(
        signed(
            relay_secret,
            NOW - 10,
            39005,
            vec![tag(&["d", "omarchy"]), tag(&["e", &message.event().id])],
        ),
        &relay,
        NOW,
        &limits(),
    )
    .expect("pins");
    state.observe_pins(&pins).expect("pins");
    state
}

async fn open_store(directory: &TempDir) -> SealedStore {
    SealedStore::open(directory.path(), RequestedProvider::File)
        .await
        .expect("open store")
}

fn record_path(directory: &TempDir, relay: &str) -> std::path::PathBuf {
    directory
        .path()
        .join("records")
        .join(format!("nip29-rooms-v1-{relay}"))
}

#[tokio::test]
async fn restart_preserves_exact_room_state_and_replay_is_idempotent() {
    let directory = TempDir::new().expect("tempdir");
    let anchor = TestGenerationAnchor::default();
    let relay = pubkey(&RELAY_SECRET);
    let state = build_state(&RELAY_SECRET);
    {
        let store = open_store(&directory).await;
        let mut vault = RoomStateVault::open(&store, &anchor, CONTEXT, &relay).expect("vault");
        let (fresh, load) = vault.load_or_create(NOW, &limits()).expect("fresh");
        assert_eq!(load, RoomStateLoad::Fresh);
        assert_eq!(fresh, RelayRoomState::new(relay.clone()).expect("empty"));
        assert_eq!(vault.persist(&state).expect("persist"), 1);
        assert_eq!(vault.persist(&state).expect("persist again"), 2);
    }

    let store = open_store(&directory).await;
    let mut vault = RoomStateVault::open(&store, &anchor, CONTEXT, &relay).expect("vault");
    let (restored, load) = vault.load_or_create(NOW, &limits()).expect("restored");
    assert_eq!(load, RoomStateLoad::Restored { generation: 2 });
    assert_eq!(restored, state);
    assert_eq!(restored.snapshot(), state.snapshot());

    // Deleted groups and events stay deleted; live evidence is intact.
    assert_eq!(
        restored.lifecycle().status("closed"),
        Some(GroupStatus::Deleted)
    );
    assert_eq!(
        restored.lifecycle().status("omarchy"),
        Some(GroupStatus::Active)
    );
    assert!(restored.lifecycle().invite("omarchy", "welcome").is_some());
    let group = restored.group("omarchy").expect("group");
    assert_eq!(group.deletions().len(), 1);
    assert!(group.membership().is_member(&pubkey(&AGENT_SECRET)));
    assert_eq!(group.admins().expect("admins").principals().len(), 1);
    assert_eq!(group.pins().expect("pins").pins().len(), 1);
    assert_eq!(
        restored
            .identities()
            .relay_pubkey("wss://relay.example")
            .expect("bound"),
        relay
    );
    let omarchy = restored.metadata().group("omarchy").expect("metadata");
    assert_eq!(omarchy.name(), "Omarchy");
    assert_eq!(omarchy.about(), "Linux talk");
    assert!(!omarchy.is_private());

    // Replaying the same accepted inputs into the restored state is a no-op.
    let mut replayed = restored.clone();
    let relay_state = build_state(&RELAY_SECRET);
    for input in relay_state.lifecycle().inputs() {
        assert_eq!(
            replayed
                .lifecycle_mut()
                .apply_accepted(input)
                .expect("replay"),
            LifecycleApplyResult::Duplicate
        );
    }
    for input in relay_state.metadata().inputs() {
        let result = match input {
            omachat_nostr::nip29_metadata::MetadataInput::Snapshot(snapshot) => {
                replayed.metadata_mut().observe_snapshot(snapshot)
            }
            omachat_nostr::nip29_metadata::MetadataInput::Edit(edit) => {
                replayed.metadata_mut().apply_accepted(edit)
            }
        };
        assert_eq!(result.expect("replay"), MetadataApplyResult::Duplicate);
    }
    let put = GroupMembershipAction::verify(
        signed(
            &MODERATOR_SECRET,
            NOW - 40,
            9000,
            vec![
                tag(&["h", "omarchy"]),
                tag(&["p", &pubkey(&AGENT_SECRET), "agent"]),
            ],
        ),
        NOW,
        &limits(),
    )
    .expect("put");
    assert_eq!(
        replayed.apply_membership(&put).expect("replay"),
        MembershipApplyResult::Idempotent
    );
    assert_eq!(replayed, restored);
}

#[tokio::test]
async fn interrupted_write_preserves_the_previous_valid_state() {
    let directory = TempDir::new().expect("tempdir");
    let anchor = TestGenerationAnchor::default();
    let relay = pubkey(&RELAY_SECRET);
    let state = build_state(&RELAY_SECRET);
    {
        let store = open_store(&directory).await;
        let mut vault = RoomStateVault::open(&store, &anchor, CONTEXT, &relay).expect("vault");
        vault.persist(&state).expect("persist");
    }
    let orphan = directory
        .path()
        .join("records")
        .join(format!(".nip29-rooms-v1-{relay}.tmp-999-1"));
    fs::write(&orphan, b"partial replacement").expect("orphan");
    // An orphaned atomic-replacement temporary is discarded on open.
    let store = open_store(&directory).await;
    assert!(!orphan.exists(), "interrupted temporary must be discarded");
    let mut vault = RoomStateVault::open(&store, &anchor, CONTEXT, &relay).expect("vault");
    let (restored, load) = vault.load_or_create(NOW, &limits()).expect("restored");
    assert_eq!(load, RoomStateLoad::Restored { generation: 1 });
    assert_eq!(restored, state);

    // A crash after the record but before the external anchor advances leaves
    // the authenticated record ahead. Load accepts it and heals the anchor.
    vault.persist(&state).expect("second generation");
    anchor.set_unchecked(CONTEXT, &relay, 1);
    let store = open_store(&directory).await;
    let mut vault = RoomStateVault::open(&store, &anchor, CONTEXT, &relay).expect("vault");
    let (_, load) = vault
        .load_or_create(NOW, &limits())
        .expect("record ahead of anchor");
    assert_eq!(load, RoomStateLoad::Restored { generation: 2 });
    assert_eq!(anchor.generation(CONTEXT, &relay), Some(2));
    assert_eq!(vault.persist(&state).expect("heal"), 3);
}

#[tokio::test]
async fn truncation_corruption_and_authentication_failures_are_rejected() {
    let directory = TempDir::new().expect("tempdir");
    let anchor = TestGenerationAnchor::default();
    let relay = pubkey(&RELAY_SECRET);
    let state = build_state(&RELAY_SECRET);
    {
        let store = open_store(&directory).await;
        let mut vault = RoomStateVault::open(&store, &anchor, CONTEXT, &relay).expect("vault");
        vault.persist(&state).expect("persist");
    }
    let record = record_path(&directory, &relay);
    let original = fs::read(&record).expect("record");

    // Bit-level corruption inside the ciphertext.
    let mut flipped = original.clone();
    let index = flipped.len() / 2;
    flipped[index] ^= 0x01;
    fs::write(&record, &flipped).expect("flip");
    let store = open_store(&directory).await;
    let mut vault = RoomStateVault::open(&store, &anchor, CONTEXT, &relay).expect("vault");
    assert!(matches!(
        vault.load_or_create(NOW, &limits()),
        Err(RoomStateVaultError::Store(StoreError::Authentication))
    ));

    // Truncation.
    fs::write(&record, &original[..original.len() - 40]).expect("truncate");
    assert!(matches!(
        vault.load_or_create(NOW, &limits()),
        Err(RoomStateVaultError::Store(StoreError::Authentication))
    ));
    fs::write(&record, &original[..12]).expect("truncate hard");
    assert!(matches!(
        vault.load_or_create(NOW, &limits()),
        Err(RoomStateVaultError::Store(StoreError::InvalidEnvelope))
    ));

    // Restored, it loads again; corruption never reset it to empty.
    fs::write(&record, &original).expect("restore");
    let (restored, _) = vault.load_or_create(NOW, &limits()).expect("restored");
    assert_eq!(restored, state);
}

#[tokio::test]
async fn rollback_is_detected() {
    let directory = TempDir::new().expect("tempdir");
    let anchor = TestGenerationAnchor::default();
    let relay = pubkey(&RELAY_SECRET);
    let state = build_state(&RELAY_SECRET);
    let record = record_path(&directory, &relay);
    let store = open_store(&directory).await;
    let mut vault = RoomStateVault::open(&store, &anchor, CONTEXT, &relay).expect("vault");
    vault.persist(&state).expect("generation 1");
    let generation_one = fs::read(&record).expect("record");
    vault.persist(&state).expect("generation 2");

    // Restoring the complete sealed-store record behind the external anchor
    // is refused. The anchor is deliberately outside the restored domain.
    fs::write(&record, generation_one).expect("roll back");
    let store = open_store(&directory).await;
    let mut vault = RoomStateVault::open(&store, &anchor, CONTEXT, &relay).expect("vault");
    assert!(matches!(
        vault.load_or_create(NOW, &limits()),
        Err(RoomStateVaultError::Rollback {
            record_generation: 1,
            anchor_generation: 2
        })
    ));

    // A vanished record with a surviving anchor is not "legitimately empty".
    fs::remove_file(&record).expect("remove record");
    assert!(matches!(
        vault.load_or_create(NOW, &limits()),
        Err(RoomStateVaultError::Rollback {
            record_generation: 0,
            anchor_generation: 2
        })
    ));
}

#[tokio::test]
async fn wrong_relay_context_and_schema_versions_are_rejected() {
    let directory = TempDir::new().expect("tempdir");
    let anchor = TestGenerationAnchor::default();
    let relay = pubkey(&RELAY_SECRET);
    let other_relay = pubkey(&OTHER_RELAY_SECRET);
    let state = build_state(&RELAY_SECRET);
    let store = open_store(&directory).await;
    let mut vault = RoomStateVault::open(&store, &anchor, CONTEXT, &relay).expect("vault");
    vault.persist(&state).expect("persist");

    // Persisting a state for another relay through this vault writes nothing.
    let foreign = build_state(&OTHER_RELAY_SECRET);
    assert!(matches!(
        vault.persist(&foreign),
        Err(RoomStateVaultError::RelayMismatch)
    ));
    assert!(!record_path(&directory, &other_relay).exists());

    // Wrong store context.
    anchor.set_unchecked("device:other", &relay, 1);
    let mut other_context =
        RoomStateVault::open(&store, &anchor, "device:other", &relay).expect("vault");
    assert!(matches!(
        other_context.load_or_create(NOW, &limits()),
        Err(RoomStateVaultError::ContextMismatch)
    ));

    // Wrong relay binding: copy the sealed bytes under the other relay's name
    // fails authentication because the record name is associated data.
    let sealed = fs::read(record_path(&directory, &relay)).expect("record");
    fs::write(record_path(&directory, &other_relay), &sealed).expect("copy");
    anchor.set_unchecked(CONTEXT, &other_relay, 1);
    let mut other_vault =
        RoomStateVault::open(&store, &anchor, CONTEXT, &other_relay).expect("vault");
    assert!(matches!(
        other_vault.load_or_create(NOW, &limits()),
        Err(RoomStateVaultError::Store(StoreError::Authentication))
    ));

    // A record sealed by this store but claiming another relay inside.
    let inner = format!(
        r#"{{"record_version":1,"store_context":"{CONTEXT}","relay_pubkey":"{relay}","generation":9,"snapshot":{}}}"#,
        serde_json::to_string(&state.snapshot()).expect("snapshot")
    );
    store
        .write(&format!("nip29-rooms-v1-{other_relay}"), inner.as_bytes())
        .expect("seal");
    anchor.set_unchecked(CONTEXT, &other_relay, 9);
    assert!(matches!(
        other_vault.load_or_create(NOW, &limits()),
        Err(RoomStateVaultError::RelayMismatch)
    ));

    // Unsupported future schema version.
    let future = format!(
        r#"{{"record_version":2,"store_context":"{CONTEXT}","relay_pubkey":"{relay}","generation":1,"snapshot":{{}}}}"#
    );
    store
        .write(&format!("nip29-rooms-v1-{relay}"), future.as_bytes())
        .expect("seal future");
    assert!(matches!(
        vault.load_or_create(NOW, &limits()),
        Err(RoomStateVaultError::UnsupportedVersion(2))
    ));

    // A record whose snapshot no longer verifies is corrupt, not empty.
    let mut snapshot = serde_json::to_value(state.snapshot()).expect("value");
    snapshot["lifecycle_inputs"][0]["event"]["content"] = serde_json::Value::String("x".into());
    let tampered = format!(
        r#"{{"record_version":1,"store_context":"{CONTEXT}","relay_pubkey":"{relay}","generation":1,"snapshot":{snapshot}}}"#
    );
    store
        .write(&format!("nip29-rooms-v1-{relay}"), tampered.as_bytes())
        .expect("seal tampered");
    assert!(matches!(
        vault.load_or_create(NOW, &limits()),
        Err(RoomStateVaultError::Corrupt(RoomStateError::Event(_)))
    ));

    assert!(matches!(
        RoomStateVault::open(&store, &anchor, "", &relay),
        Err(RoomStateVaultError::InvalidContext)
    ));
    assert!(matches!(
        RoomStateVault::open(&store, &anchor, CONTEXT, "relay"),
        Err(RoomStateVaultError::InvalidRelayPublicKey)
    ));
}

#[tokio::test]
async fn multiple_relays_stay_isolated_in_one_store() {
    let directory = TempDir::new().expect("tempdir");
    let anchor = TestGenerationAnchor::default();
    let relay = pubkey(&RELAY_SECRET);
    let other_relay = pubkey(&OTHER_RELAY_SECRET);
    let first = build_state(&RELAY_SECRET);
    let second = build_state(&OTHER_RELAY_SECRET);
    {
        let store = open_store(&directory).await;
        RoomStateVault::open(&store, &anchor, CONTEXT, &relay)
            .expect("vault")
            .persist(&first)
            .expect("persist");
        RoomStateVault::open(&store, &anchor, CONTEXT, &other_relay)
            .expect("vault")
            .persist(&second)
            .expect("persist");
    }
    let store = open_store(&directory).await;
    let (restored_first, _) = RoomStateVault::open(&store, &anchor, CONTEXT, &relay)
        .expect("vault")
        .load_or_create(NOW, &limits())
        .expect("first");
    let (restored_second, _) = RoomStateVault::open(&store, &anchor, CONTEXT, &other_relay)
        .expect("vault")
        .load_or_create(NOW, &limits())
        .expect("second");
    assert_eq!(restored_first, first);
    assert_eq!(restored_second, second);
    assert_ne!(restored_first, restored_second);
    assert_eq!(restored_first.relay_pubkey(), relay);
    assert_eq!(restored_second.relay_pubkey(), other_relay);
    // Same group IDs, different relays: distinct scopes.
    assert_eq!(
        restored_first
            .group("omarchy")
            .expect("group")
            .membership()
            .relay_pubkey(),
        relay
    );
    assert_eq!(
        restored_second
            .group("omarchy")
            .expect("group")
            .membership()
            .relay_pubkey(),
        other_relay
    );
}
