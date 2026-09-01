use omachat_nostr::{
    event::{EventLimits, SignedEvent, UnsignedEvent, xonly_public_key},
    nip29::{
        GROUP_MESSAGE_KIND, GROUP_METADATA_KIND, GroupEventError, GroupMembershipAction,
        GroupMetadata, GroupRoster, GroupRosterKind, GroupUserAction, GroupUserEvent,
        MembershipAction, group_message, join_request, leave_request,
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

#[test]
fn relay_signed_metadata_exposes_discord_class_room_properties() {
    let limits = EventLimits::default();
    let relay_pubkey = pubkey(&OWNER_SECRET);
    let event = UnsignedEvent::new(
        relay_pubkey.clone(),
        NOW,
        GROUP_METADATA_KIND,
        vec![
            vec!["d".to_owned(), "omarchy".to_owned()],
            vec!["name".to_owned(), "Omarchy".to_owned()],
            vec!["about".to_owned(), "Community room".to_owned()],
            vec!["private".to_owned()],
            vec!["restricted".to_owned()],
            vec!["livekit".to_owned()],
            vec![
                "supported_kinds".to_owned(),
                "9".to_owned(),
                "11".to_owned(),
            ],
            vec!["parent".to_owned(), "linux".to_owned()],
            vec!["child".to_owned(), "install-help".to_owned()],
            vec!["child".to_owned(), "showcase".to_owned()],
        ],
        String::new(),
        &limits,
    )
    .expect("metadata event");
    let metadata = GroupMetadata::verify(sign(event, &OWNER_SECRET), &relay_pubkey, NOW, &limits)
        .expect("relay-authenticated metadata");

    assert_eq!(metadata.group_id(), "omarchy");
    assert_eq!(metadata.name(), Some("Omarchy"));
    assert_eq!(metadata.about(), Some("Community room"));
    assert!(metadata.is_private());
    assert!(metadata.is_restricted());
    assert!(!metadata.is_hidden());
    assert!(metadata.supports_livekit());
    assert_eq!(metadata.supported_kinds(), Some([9, 11].as_slice()));
    assert_eq!(metadata.parent(), Some("linux"));
    assert_eq!(metadata.children(), ["install-help", "showcase"]);
}

#[test]
fn metadata_requires_the_expected_relay_key() {
    let limits = EventLimits::default();
    let event = UnsignedEvent::new(
        pubkey(&AGENT_SECRET),
        NOW,
        GROUP_METADATA_KIND,
        vec![vec!["d".to_owned(), "room".to_owned()]],
        String::new(),
        &limits,
    )
    .expect("metadata event");

    assert!(matches!(
        GroupMetadata::verify(
            sign(event, &AGENT_SECRET),
            &pubkey(&OWNER_SECRET),
            NOW,
            &limits,
        ),
        Err(GroupEventError::RelayAuthorMismatch)
    ));
}

#[test]
fn absent_and_empty_supported_kinds_remain_distinct() {
    let limits = EventLimits::default();
    let relay_pubkey = pubkey(&OWNER_SECRET);
    let metadata = |tags| {
        let event = UnsignedEvent::new(
            relay_pubkey.clone(),
            NOW,
            GROUP_METADATA_KIND,
            tags,
            String::new(),
            &limits,
        )
        .expect("metadata event");
        GroupMetadata::verify(sign(event, &OWNER_SECRET), &relay_pubkey, NOW, &limits)
            .expect("metadata verifies")
    };

    assert_eq!(
        metadata(vec![vec!["d".to_owned(), "all-kinds".to_owned()]]).supported_kinds(),
        None
    );
    assert_eq!(
        metadata(vec![
            vec!["d".to_owned(), "av-only".to_owned()],
            vec!["livekit".to_owned()],
            vec!["supported_kinds".to_owned()],
        ])
        .supported_kinds(),
        Some([].as_slice())
    );
}

#[test]
fn ambiguous_metadata_tags_fail_closed() {
    let limits = EventLimits::default();
    let relay_pubkey = pubkey(&OWNER_SECRET);
    for tags in [
        vec![
            vec!["d".to_owned(), "one".to_owned()],
            vec!["d".to_owned(), "two".to_owned()],
        ],
        vec![
            vec!["d".to_owned(), "room".to_owned()],
            vec!["private".to_owned(), "false".to_owned()],
        ],
        vec![
            vec!["d".to_owned(), "room".to_owned()],
            vec!["supported_kinds".to_owned(), "nine".to_owned()],
        ],
    ] {
        let event = UnsignedEvent::new(
            relay_pubkey.clone(),
            NOW,
            GROUP_METADATA_KIND,
            tags,
            String::new(),
            &limits,
        )
        .expect("bounded metadata");
        assert!(
            GroupMetadata::verify(sign(event, &OWNER_SECRET), &relay_pubkey, NOW, &limits,)
                .is_err()
        );
    }
}

#[test]
fn relay_signed_admin_roles_preserve_principal_identity() {
    let limits = EventLimits::default();
    let relay_pubkey = pubkey(&OWNER_SECRET);
    let agent_pubkey = pubkey(&AGENT_SECRET);
    let event = UnsignedEvent::new(
        relay_pubkey.clone(),
        NOW,
        39001,
        vec![
            vec!["d".to_owned(), "omarchy".to_owned()],
            vec![
                "p".to_owned(),
                agent_pubkey.clone(),
                "moderator".to_owned(),
                "agent".to_owned(),
            ],
        ],
        "published admins".to_owned(),
        &limits,
    )
    .expect("admin snapshot");
    let roster = GroupRoster::verify(sign(event, &OWNER_SECRET), &relay_pubkey, NOW, &limits)
        .expect("relay-authenticated admins");

    assert_eq!(roster.kind(), GroupRosterKind::Admins);
    assert_eq!(roster.group_id(), "omarchy");
    assert_eq!(roster.principals()[0].pubkey(), agent_pubkey);
    assert_eq!(roster.principals()[0].roles(), ["moderator", "agent"]);
}

#[test]
fn published_members_are_explicitly_a_distinct_snapshot_kind() {
    let limits = EventLimits::default();
    let relay_pubkey = pubkey(&OWNER_SECRET);
    let event = UnsignedEvent::new(
        relay_pubkey.clone(),
        NOW,
        39002,
        vec![
            vec!["d".to_owned(), "omarchy".to_owned()],
            vec!["p".to_owned(), pubkey(&AGENT_SECRET)],
        ],
        "possibly partial members".to_owned(),
        &limits,
    )
    .expect("member snapshot");
    let roster = GroupRoster::verify(sign(event, &OWNER_SECRET), &relay_pubkey, NOW, &limits)
        .expect("relay-authenticated members");

    assert_eq!(roster.kind(), GroupRosterKind::PublishedMembers);
    assert!(roster.principals()[0].roles().is_empty());
}

#[test]
fn forged_ambiguous_and_malformed_rosters_fail_closed() {
    let limits = EventLimits::default();
    let relay_pubkey = pubkey(&OWNER_SECRET);
    let agent_pubkey = pubkey(&AGENT_SECRET);
    for (kind, tags) in [
        (
            39001,
            vec![
                vec!["d".to_owned(), "room".to_owned()],
                vec!["p".to_owned(), agent_pubkey.clone()],
            ],
        ),
        (
            39002,
            vec![
                vec!["d".to_owned(), "room".to_owned()],
                vec!["p".to_owned(), agent_pubkey.clone()],
                vec!["p".to_owned(), agent_pubkey.clone()],
            ],
        ),
        (
            39002,
            vec![
                vec!["d".to_owned(), "room".to_owned()],
                vec!["p".to_owned(), "not-a-pubkey".to_owned()],
            ],
        ),
    ] {
        let event = UnsignedEvent::new(
            relay_pubkey.clone(),
            NOW,
            kind,
            tags,
            String::new(),
            &limits,
        )
        .expect("bounded snapshot");
        assert!(
            GroupRoster::verify(sign(event, &OWNER_SECRET), &relay_pubkey, NOW, &limits,).is_err()
        );
    }

    let forged = UnsignedEvent::new(
        agent_pubkey,
        NOW,
        39002,
        vec![vec!["d".to_owned(), "room".to_owned()]],
        String::new(),
        &limits,
    )
    .expect("forged snapshot");
    assert!(matches!(
        GroupRoster::verify(sign(forged, &AGENT_SECRET), &relay_pubkey, NOW, &limits,),
        Err(GroupEventError::RelayAuthorMismatch)
    ));
}

#[test]
fn membership_actions_preserve_moderator_and_target_principals() {
    let limits = EventLimits::default();
    let moderator_pubkey = pubkey(&OWNER_SECRET);
    let agent_pubkey = pubkey(&AGENT_SECRET);
    let event = UnsignedEvent::new(
        moderator_pubkey.clone(),
        NOW,
        9000,
        vec![
            vec!["h".to_owned(), "omarchy".to_owned()],
            vec![
                "p".to_owned(),
                agent_pubkey.clone(),
                "moderator".to_owned(),
                "agent".to_owned(),
            ],
            vec!["previous".to_owned(), "eb96c864".to_owned()],
        ],
        "grant room roles".to_owned(),
        &limits,
    )
    .expect("membership action");
    let action = GroupMembershipAction::verify(sign(event, &OWNER_SECRET), NOW, &limits)
        .expect("authenticated action");

    assert_eq!(action.author(), moderator_pubkey);
    assert_eq!(action.group_id(), "omarchy");
    assert_eq!(action.previous(), ["eb96c864"]);
    assert_eq!(
        action.action(),
        &MembershipAction::Put {
            pubkey: agent_pubkey,
            roles: vec!["moderator".to_owned(), "agent".to_owned()],
        }
    );
}

#[test]
fn valid_signature_does_not_turn_membership_action_into_authority() {
    let limits = EventLimits::default();
    let attacker_pubkey = pubkey(&AGENT_SECRET);
    let event = UnsignedEvent::new(
        attacker_pubkey.clone(),
        NOW,
        9001,
        vec![
            vec!["h".to_owned(), "omarchy".to_owned()],
            vec!["p".to_owned(), pubkey(&OWNER_SECRET)],
        ],
        "attempt removal".to_owned(),
        &limits,
    )
    .expect("signed action");
    let action = GroupMembershipAction::verify(sign(event, &AGENT_SECRET), NOW, &limits)
        .expect("signature is authentic");

    assert_eq!(action.author(), attacker_pubkey);
    assert!(matches!(action.action(), MembershipAction::Remove { .. }));
    // This type makes no claim that the relay accepted the request or that its
    // author holds a role capable of removing a member.
}

#[test]
fn malformed_membership_targets_fail_closed() {
    let limits = EventLimits::default();
    for (kind, tags) in [
        (9000, vec![vec!["h".to_owned(), "room".to_owned()]]),
        (
            9000,
            vec![
                vec!["h".to_owned(), "room".to_owned()],
                vec!["p".to_owned(), pubkey(&AGENT_SECRET)],
                vec!["p".to_owned(), pubkey(&OWNER_SECRET)],
            ],
        ),
        (
            9001,
            vec![
                vec!["h".to_owned(), "room".to_owned()],
                vec![
                    "p".to_owned(),
                    pubkey(&AGENT_SECRET),
                    "role-not-allowed".to_owned(),
                ],
            ],
        ),
    ] {
        let event = UnsignedEvent::new(
            pubkey(&OWNER_SECRET),
            NOW,
            kind,
            tags,
            String::new(),
            &limits,
        )
        .expect("bounded action");
        assert!(GroupMembershipAction::verify(sign(event, &OWNER_SECRET), NOW, &limits).is_err());
    }
}
