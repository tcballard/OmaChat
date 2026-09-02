use omachat_nostr::{
    discovery::{RelayDiscoveryLimits, RelayPreference, parse_nip65_relay_list},
    event::EventLimits,
    relay_list::{RelayListPublicationError, create_nip65_relay_list_with_aux},
};

#[test]
fn publication_allows_only_numeric_loopback_plaintext_relays() {
    let secret = [171; 32];
    let event = create_nip65_relay_list_with_aux(
        &secret,
        1_000,
        &[
            RelayPreference {
                url: "ws://127.0.0.1:7447".into(),
                read: true,
                write: true,
            },
            RelayPreference {
                url: "ws://[::1]:7448".into(),
                read: true,
                write: false,
            },
        ],
        &[172; 32],
        &EventLimits::default(),
        &RelayDiscoveryLimits::default(),
    )
    .expect("numeric loopback should support hermetic publication");
    let parsed = parse_nip65_relay_list(
        &event,
        1_000,
        &EventLimits::default(),
        &RelayDiscoveryLimits::default(),
    )
    .unwrap();
    assert_eq!(parsed.relays[0].url, "ws://127.0.0.1:7447/");
    assert_eq!(parsed.relays[1].url, "ws://[::1]:7448/");

    assert!(matches!(
        create_nip65_relay_list_with_aux(
            &secret,
            1_000,
            &[RelayPreference {
                url: "ws://relay.example".into(),
                read: true,
                write: true,
            }],
            &[173; 32],
            &EventLimits::default(),
            &RelayDiscoveryLimits::default(),
        ),
        Err(RelayListPublicationError::InvalidEndpoint)
    ));
}
