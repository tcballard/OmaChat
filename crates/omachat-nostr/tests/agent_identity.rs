use omachat_crypto::{AccountSecrets, AgentAuthorizationRequest, DisplayName};
use omachat_nostr::event::{EventError, EventLimits, UnsignedEvent};

#[test]
fn authorized_agent_remains_the_nostr_event_author() {
    let limits = EventLimits::default();
    let owner = AccountSecrets::from_seeds([1; 32], [2; 32]);
    let agent_secret = [0x31; 32];
    let request = AgentAuthorizationRequest::sign(
        &agent_secret,
        owner.public_identity().account_id,
        Some(DisplayName::parse("External Agent").unwrap()),
        1_788_100_000,
        &[0x42; 32],
    )
    .unwrap();
    let authorization = owner.authorize_agent(request, 1, 1_788_100_001).unwrap();
    authorization.verify().unwrap();

    let event = UnsignedEvent::new(
        hex::encode(authorization.agent_public_key()),
        1_788_100_010,
        1,
        vec![],
        "agent-authored".into(),
        &limits,
    )
    .unwrap()
    .sign_with_aux(&agent_secret, &[0x43; 32], &limits)
    .unwrap();
    event.verify(1_788_100_010, &limits).unwrap();
    assert_eq!(event.pubkey, hex::encode(authorization.agent_public_key()));
    assert_ne!(
        event.pubkey,
        hex::encode(owner.public_identity().account_root_public_key)
    );

    let owner_key_cannot_author_agent_event = UnsignedEvent::new(
        hex::encode(authorization.agent_public_key()),
        1_788_100_011,
        1,
        vec![],
        "not-owner-authored".into(),
        &limits,
    )
    .unwrap()
    .sign_with_aux(&[1; 32], &[0x44; 32], &limits);
    assert!(matches!(
        owner_key_cannot_author_agent_event,
        Err(EventError::PublicKeyMismatch)
    ));
}
