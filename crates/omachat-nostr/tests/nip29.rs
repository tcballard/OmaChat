use omachat_nostr::{
    event::{EventLimits, SignedEvent, UnsignedEvent, xonly_public_key},
    nip29::{
        GROUP_MESSAGE_KIND, GroupEventError, GroupUserAction, GroupUserEvent, group_message,
        join_request, leave_request,
    },
};

const NOW: u64 = 1_800_000_000;
const AGENT_SECRET: [u8; 32] = [7; 32];
const OWNER_SECRET: [u8; 32] = [9; 32];

fn pubkey(secret: &[u8; 32]) -> String {
    hex::encode(xonly_public_key(secret).expect("valid key"))
}

fn sign(event: UnsignedEvent, secret: &[u8; 32]) -> SignedEvent {
    event
        .sign_with_aux(secret, &[3; 32], &EventLimits::default())
        .expect("event signs")
}

#[test]
fn buzz_compatible_room_message_preserves_agent_authorship() {
    let limits = EventLimits::default();
    let unsigned = group_message(
        pubkey(&AGENT_SECRET),
        NOW,
        "018f-room",
        "agent-authored update".to_owned(),
        &["eb96c864".to_owned(), "2db75638".to_owned()],
        &limits,
    )
    .expect("NIP-29 message");
    let signed = sign(unsigned, &AGENT_SECRET);
    let parsed = GroupUserEvent::verify(signed.clone(), NOW, &limits).expect("verified room event");

    assert_eq!(signed.kind, GROUP_MESSAGE_KIND);
    assert_eq!(parsed.author(), pubkey(&AGENT_SECRET));
    assert_ne!(parsed.author(), pubkey(&OWNER_SECRET));
    assert_eq!(parsed.group_id(), "018f-room");
    assert_eq!(parsed.action(), &GroupUserAction::Message);
    assert_eq!(parsed.previous(), ["eb96c864", "2db75638"]);
}

#[test]
fn join_and_leave_follow_the_standard_user_event_shapes() {
    let limits = EventLimits::default();
    let join = sign(
        join_request(
            pubkey(&AGENT_SECRET),
            NOW,
            "community-room",
            "invited by Tom".to_owned(),
            Some("invite-123"),
            &[],
            &limits,
        )
        .expect("join request"),
        &AGENT_SECRET,
    );
    let leave = sign(
        leave_request(
            pubkey(&AGENT_SECRET),
            NOW,
            "community-room",
            String::new(),
            &[],
            &limits,
        )
        .expect("leave request"),
        &AGENT_SECRET,
    );

    assert_eq!(
        GroupUserEvent::verify(join, NOW, &limits)
            .expect("verified join")
            .action(),
        &GroupUserAction::Join {
            invite_code: Some("invite-123".to_owned())
        }
    );
    assert_eq!(
        GroupUserEvent::verify(leave, NOW, &limits)
            .expect("verified leave")
            .action(),
        &GroupUserAction::Leave
    );
}

#[test]
fn ambiguous_group_and_invite_tags_fail_closed() {
    let limits = EventLimits::default();
    for tags in [
        vec![
            vec!["h".to_owned(), "one".to_owned()],
            vec!["h".to_owned(), "two".to_owned()],
        ],
        vec![vec![
            "h".to_owned(),
            "one".to_owned(),
            "smuggled".to_owned(),
        ]],
        vec![
            vec!["h".to_owned(), "one".to_owned()],
            vec!["code".to_owned(), "invite".to_owned()],
        ],
    ] {
        let event = UnsignedEvent::new(
            pubkey(&AGENT_SECRET),
            NOW,
            GROUP_MESSAGE_KIND,
            tags,
            "hello".to_owned(),
            &limits,
        )
        .expect("bounded event");
        assert!(GroupUserEvent::verify(sign(event, &AGENT_SECRET), NOW, &limits).is_err());
    }
}

#[test]
fn invalid_timeline_references_and_unsupported_kinds_fail_closed() {
    let limits = EventLimits::default();
    for reference in ["eb96c86", "EB96C864", "zz96c864"] {
        assert!(matches!(
            group_message(
                pubkey(&AGENT_SECRET),
                NOW,
                "room",
                "hello".to_owned(),
                &[reference.to_owned()],
                &limits,
            ),
            Err(GroupEventError::InvalidTimelineReference)
        ));
    }

    let unsupported = UnsignedEvent::new(
        pubkey(&AGENT_SECRET),
        NOW,
        1,
        vec![vec!["h".to_owned(), "room".to_owned()]],
        "not a supported room message".to_owned(),
        &limits,
    )
    .expect("bounded event");
    assert!(matches!(
        GroupUserEvent::verify(sign(unsupported, &AGENT_SECRET), NOW, &limits),
        Err(GroupEventError::UnsupportedKind(1))
    ));
}

#[test]
fn relay_origin_never_substitutes_for_a_valid_signature() {
    let limits = EventLimits::default();
    let mut event = sign(
        group_message(
            pubkey(&AGENT_SECRET),
            NOW,
            "room",
            "authentic content".to_owned(),
            &[],
            &limits,
        )
        .expect("message"),
        &AGENT_SECRET,
    );
    event.content = "relay-tampered content".to_owned();

    assert!(matches!(
        GroupUserEvent::verify(event, NOW, &limits),
        Err(GroupEventError::Event(_))
    ));
}
