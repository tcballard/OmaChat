use omachat_nostr::{
    event::{EventLimits, UnsignedEvent, xonly_public_key},
    nip29_roles::{GROUP_ROLES_KIND, GroupRoles, GroupRolesError},
};

const NOW: u64 = 1_800_000_000;
const RELAY_SECRET: [u8; 32] = [5; 32];
const OTHER_SECRET: [u8; 32] = [7; 32];

fn pubkey(secret: &[u8; 32]) -> String {
    hex::encode(xonly_public_key(secret).expect("valid key"))
}

fn signed_roles(tags: Vec<Vec<String>>, secret: &[u8; 32]) -> omachat_nostr::event::SignedEvent {
    let limits = EventLimits::default();
    UnsignedEvent::new(
        pubkey(secret),
        NOW,
        GROUP_ROLES_KIND,
        tags,
        "relay-defined roles".to_owned(),
        &limits,
    )
    .expect("role event")
    .sign_with_aux(secret, &[3; 32], &limits)
    .expect("signed role event")
}

#[test]
fn relay_defined_roles_preserve_labels_without_inventing_capabilities() {
    let limits = EventLimits::default();
    let relay = pubkey(&RELAY_SECRET);
    let roles = GroupRoles::verify(
        signed_roles(
            vec![
                vec!["d".to_owned(), "omarchy".to_owned()],
                vec![
                    "role".to_owned(),
                    "maintainer".to_owned(),
                    "Can manage this relay's room".to_owned(),
                ],
                vec!["role".to_owned(), "agent-reviewer".to_owned()],
            ],
            &RELAY_SECRET,
        ),
        &relay,
        NOW,
        &limits,
    )
    .expect("relay-authenticated roles");

    assert_eq!(roles.group_id(), "omarchy");
    assert_eq!(roles.roles()[0].name(), "maintainer");
    assert_eq!(
        roles.roles()[0].description(),
        Some("Can manage this relay's room")
    );
    assert_eq!(roles.roles()[1].name(), "agent-reviewer");
    assert_eq!(roles.roles()[1].description(), None);
}

#[test]
fn another_valid_nostr_key_cannot_define_this_relays_roles() {
    let limits = EventLimits::default();
    assert!(matches!(
        GroupRoles::verify(
            signed_roles(
                vec![
                    vec!["d".to_owned(), "omarchy".to_owned()],
                    vec!["role".to_owned(), "owner".to_owned()],
                ],
                &OTHER_SECRET,
            ),
            &pubkey(&RELAY_SECRET),
            NOW,
            &limits,
        ),
        Err(GroupRolesError::RelayAuthorMismatch)
    ));
}

#[test]
fn malformed_ambiguous_and_duplicate_role_state_fails_closed() {
    let limits = EventLimits::default();
    let relay = pubkey(&RELAY_SECRET);
    for tags in [
        vec![
            vec!["d".to_owned(), "one".to_owned()],
            vec!["d".to_owned(), "two".to_owned()],
        ],
        vec![
            vec!["d".to_owned(), "room".to_owned()],
            vec!["role".to_owned(), String::new()],
        ],
        vec![
            vec!["d".to_owned(), "room".to_owned()],
            vec!["role".to_owned(), "admin".to_owned()],
            vec![
                "role".to_owned(),
                "admin".to_owned(),
                "duplicate".to_owned(),
            ],
        ],
        vec![
            vec!["d".to_owned(), "room".to_owned()],
            vec![
                "role".to_owned(),
                "admin".to_owned(),
                "description".to_owned(),
                "smuggled".to_owned(),
            ],
        ],
    ] {
        assert!(
            GroupRoles::verify(signed_roles(tags, &RELAY_SECRET), &relay, NOW, &limits,).is_err()
        );
    }
}
