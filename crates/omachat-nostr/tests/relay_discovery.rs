use omachat_nostr::{
    discovery::{
        NIP17_DM_RELAY_LIST_KIND, NIP65_RELAY_LIST_KIND, RelayDiscoveryError, RelayDiscoveryLimits,
        parse_nip17_dm_relay_list, parse_nip65_relay_list,
    },
    event::{EventLimits, SignedEvent, UnsignedEvent, xonly_public_key},
};

const NOW: u64 = 1_788_200_000;

fn signed_event(secret: &[u8; 32], kind: u32, tags: Vec<Vec<String>>) -> SignedEvent {
    UnsignedEvent::new(
        hex::encode(xonly_public_key(secret).unwrap()),
        NOW,
        kind,
        tags,
        String::new(),
        &EventLimits::default(),
    )
    .unwrap()
    .sign_with_aux(secret, &[0x51; 32], &EventLimits::default())
    .unwrap()
}

#[test]
fn nip65_preserves_markers_and_merges_canonical_duplicates() {
    let secret = [0x31; 32];
    let event = signed_event(
        &secret,
        NIP65_RELAY_LIST_KIND,
        vec![
            vec!["r".into(), "wss://relay.example".into(), "read".into()],
            vec!["r".into(), "wss://relay.example/".into(), "write".into()],
            vec!["r".into(), "wss://other.example/chat".into()],
            vec!["client".into(), "ignored-extension".into()],
        ],
    );
    let list = parse_nip65_relay_list(
        &event,
        NOW,
        &EventLimits::default(),
        &RelayDiscoveryLimits::default(),
    )
    .unwrap();

    assert_eq!(
        list.public_key,
        hex::encode(xonly_public_key(&secret).unwrap())
    );
    assert_eq!(list.relays.len(), 2);
    assert_eq!(list.relays[0].url, "wss://relay.example/");
    assert!(list.relays[0].read);
    assert!(list.relays[0].write);
    assert_eq!(list.relays[1].url, "wss://other.example/chat");
}

#[test]
fn nip17_dm_relays_keep_external_identity_and_deduplicate() {
    let external_agent_secret = [0x32; 32];
    let event = signed_event(
        &external_agent_secret,
        NIP17_DM_RELAY_LIST_KIND,
        vec![
            vec!["relay".into(), "wss://inbox.example".into()],
            vec!["relay".into(), "wss://inbox.example/".into()],
            vec!["relay".into(), "wss://backup.example/agent".into()],
        ],
    );
    let list = parse_nip17_dm_relay_list(
        &event,
        NOW,
        &EventLimits::default(),
        &RelayDiscoveryLimits::default(),
    )
    .unwrap();

    assert_eq!(list.public_key, event.pubkey);
    assert_eq!(list.relays.len(), 2);
    assert!(list.relays.iter().all(|relay| relay.read && relay.write));
}

#[test]
fn relay_source_never_overrides_signature_or_event_author() {
    let mut event = signed_event(
        &[0x33; 32],
        NIP65_RELAY_LIST_KIND,
        vec![vec!["r".into(), "wss://relay.example".into()]],
    );
    event.tags[0][1] = "wss://attacker.example".into();
    assert!(matches!(
        parse_nip65_relay_list(
            &event,
            NOW,
            &EventLimits::default(),
            &RelayDiscoveryLimits::default(),
        ),
        Err(RelayDiscoveryError::InvalidEvent(_))
    ));
}

#[test]
fn malformed_unbounded_and_missing_lists_fail_closed() {
    let invalid_marker = signed_event(
        &[0x34; 32],
        NIP65_RELAY_LIST_KIND,
        vec![vec![
            "r".into(),
            "wss://relay.example".into(),
            "both".into(),
        ]],
    );
    assert_eq!(
        parse_nip65_relay_list(
            &invalid_marker,
            NOW,
            &EventLimits::default(),
            &RelayDiscoveryLimits::default(),
        ),
        Err(RelayDiscoveryError::InvalidRelayTag)
    );

    let invalid_url = signed_event(
        &[0x35; 32],
        NIP17_DM_RELAY_LIST_KIND,
        vec![vec!["relay".into(), "https://not-websocket.example".into()]],
    );
    assert_eq!(
        parse_nip17_dm_relay_list(
            &invalid_url,
            NOW,
            &EventLimits::default(),
            &RelayDiscoveryLimits::default(),
        ),
        Err(RelayDiscoveryError::InvalidRelayUrl)
    );

    let empty = signed_event(&[0x36; 32], NIP17_DM_RELAY_LIST_KIND, vec![]);
    assert_eq!(
        parse_nip17_dm_relay_list(
            &empty,
            NOW,
            &EventLimits::default(),
            &RelayDiscoveryLimits::default(),
        ),
        Err(RelayDiscoveryError::EmptyRelayList)
    );

    let too_many = signed_event(
        &[0x37; 32],
        NIP65_RELAY_LIST_KIND,
        vec![
            vec!["r".into(), "wss://one.example".into()],
            vec!["r".into(), "wss://two.example".into()],
        ],
    );
    assert_eq!(
        parse_nip65_relay_list(
            &too_many,
            NOW,
            &EventLimits::default(),
            &RelayDiscoveryLimits {
                max_relays: 1,
                max_url_bytes: 2_048,
            },
        ),
        Err(RelayDiscoveryError::TooManyRelays { maximum: 1 })
    );
}
