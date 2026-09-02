use omachat_nostr::{
    discovery::{
        NIP65_RELAY_LIST_KIND, RelayDiscoveryLimits, RelayPreference, parse_nip65_relay_list,
    },
    event::{EventLimits, xonly_public_key},
    relay_list::{RelayListPublicationError, create_nip65_relay_list_with_aux},
};

const NOW: u64 = 1_800_000_000;

fn relay(url: &str, read: bool, write: bool) -> RelayPreference {
    RelayPreference {
        url: url.to_owned(),
        read,
        write,
    }
}

#[test]
fn external_nostr_key_signs_its_own_standard_relay_list() {
    let external_secret = [71; 32];
    let external_public_key = xonly_public_key(&external_secret).expect("external public key");
    let limits = RelayDiscoveryLimits::default();
    let event = create_nip65_relay_list_with_aux(
        &external_secret,
        NOW,
        &[
            relay("wss://write.example", false, true),
            relay("wss://read.example/path", true, false),
        ],
        &[1; 32],
        &EventLimits::default(),
        &limits,
    )
    .expect("signed NIP-65 relay list");

    assert_eq!(event.kind, NIP65_RELAY_LIST_KIND);
    assert_eq!(event.pubkey, hex::encode(external_public_key));
    assert!(event.content.is_empty());
    let parsed = parse_nip65_relay_list(&event, NOW, &EventLimits::default(), &limits)
        .expect("standard parser accepts the signed event");
    assert_eq!(parsed.public_key, hex::encode(external_public_key));
    assert_eq!(
        parsed.relays,
        vec![
            relay("wss://read.example/path", true, false),
            relay("wss://write.example/", false, true),
        ]
    );
}

#[test]
fn canonical_duplicates_merge_and_input_order_does_not_change_identity() {
    let secret = [72; 32];
    let limits = RelayDiscoveryLimits::default();
    let forward = [
        relay("wss://same.example", true, false),
        relay("wss://other.example", true, true),
        relay("wss://same.example/", false, true),
    ];
    let reverse = [
        relay("wss://same.example/", false, true),
        relay("wss://other.example/", true, true),
        relay("wss://same.example", true, false),
    ];
    let first = create_nip65_relay_list_with_aux(
        &secret,
        NOW,
        &forward,
        &[2; 32],
        &EventLimits::default(),
        &limits,
    )
    .expect("first signed list");
    let second = create_nip65_relay_list_with_aux(
        &secret,
        NOW,
        &reverse,
        &[2; 32],
        &EventLimits::default(),
        &limits,
    )
    .expect("second signed list");

    assert_eq!(first.id, second.id);
    assert_eq!(first.sig, second.sig);
    assert_eq!(
        first.tags,
        vec![
            vec!["r".to_owned(), "wss://other.example/".to_owned()],
            vec!["r".to_owned(), "wss://same.example/".to_owned()],
        ]
    );
}

#[test]
fn invalid_insecure_ambiguous_and_unbounded_lists_fail_before_signing() {
    let secret = [73; 32];
    let event_limits = EventLimits::default();
    let limits = RelayDiscoveryLimits {
        max_relays: 1,
        max_url_bytes: 64,
    };

    assert_eq!(
        create_nip65_relay_list_with_aux(&secret, NOW, &[], &[3; 32], &event_limits, &limits,),
        Err(RelayListPublicationError::NoRelays)
    );
    assert_eq!(
        create_nip65_relay_list_with_aux(
            &secret,
            NOW,
            &[relay("wss://relay.example", false, false)],
            &[3; 32],
            &event_limits,
            &limits,
        ),
        Err(RelayListPublicationError::InvalidPreference)
    );
    for endpoint in [
        "ws://relay.example",
        "wss://user@relay.example",
        "wss://relay.example?token=ambient",
        "wss://relay.example#fragment",
    ] {
        assert_eq!(
            create_nip65_relay_list_with_aux(
                &secret,
                NOW,
                &[relay(endpoint, true, true)],
                &[3; 32],
                &event_limits,
                &limits,
            ),
            Err(RelayListPublicationError::InvalidEndpoint)
        );
    }
    assert_eq!(
        create_nip65_relay_list_with_aux(
            &secret,
            NOW,
            &[
                relay("wss://one.example", true, true),
                relay("wss://two.example", true, true),
            ],
            &[3; 32],
            &event_limits,
            &limits,
        ),
        Err(RelayListPublicationError::TooManyRelays { maximum: 1 })
    );
    assert_eq!(
        create_nip65_relay_list_with_aux(
            &secret,
            NOW,
            &[relay("wss://relay.example", true, true)],
            &[3; 32],
            &event_limits,
            &RelayDiscoveryLimits {
                max_relays: 0,
                max_url_bytes: 64,
            },
        ),
        Err(RelayListPublicationError::InvalidLimits)
    );
}
