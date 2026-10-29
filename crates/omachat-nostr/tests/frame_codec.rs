use omachat_nostr::{
    event::{EventError, EventLimits, SignedEvent, UnsignedEvent},
    frame::{ClientFrame, FrameError, FrameLimits, RelayFrame},
};
use serde_json::json;

fn signed_event() -> SignedEvent {
    let limits = EventLimits::default();
    UnsignedEvent::new(
        "4f355bdcb7cc0af728ef3cceb9615d90684bb5b2ca5f859ab0f0b704075871aa".into(),
        1_700_000_000,
        1,
        vec![],
        "synthetic".into(),
        &limits,
    )
    .unwrap()
    .sign_with_aux(&[0x11; 32], &[0; 32], &limits)
    .unwrap()
}

#[test]
fn encodes_supported_client_frames_compactly() {
    let limits = FrameLimits::default();
    let event = signed_event();
    let event_json = ClientFrame::Event(event.clone()).to_json(&limits).unwrap();
    assert_eq!(
        serde_json::from_slice::<serde_json::Value>(&event_json).unwrap()[0],
        "EVENT"
    );

    let request = ClientFrame::Request {
        subscription_id: "geo:gcpvj".into(),
        filters: vec![json!({"kinds":[20000],"#g":["gcpvj"]})],
    }
    .to_json(&limits)
    .unwrap();
    assert_eq!(
        request,
        br##"["REQ","geo:gcpvj",{"#g":["gcpvj"],"kinds":[20000]}]"##
    );
    assert_eq!(
        ClientFrame::Close {
            subscription_id: "geo:gcpvj".into()
        }
        .to_json(&limits)
        .unwrap(),
        br#"["CLOSE","geo:gcpvj"]"#
    );
    assert_eq!(
        serde_json::from_slice::<serde_json::Value>(
            &ClientFrame::Auth(event).to_json(&limits).unwrap()
        )
        .unwrap()[0],
        "AUTH"
    );
}

#[test]
fn decodes_and_authenticates_supported_relay_frames() {
    let event_limits = EventLimits::default();
    let frame_limits = FrameLimits::default();
    let event = signed_event();
    let event_frame = serde_json::to_vec(&("EVENT", "sub", &event)).unwrap();
    assert!(matches!(
        RelayFrame::from_json(&event_frame, 1_700_000_000, &event_limits, &frame_limits).unwrap(),
        RelayFrame::Event { .. }
    ));

    for (bytes, expected) in [
        (br#"["EOSE","sub"]"#.as_slice(), "eose"),
        (
            br#"["OK","0000000000000000000000000000000000000000000000000000000000000000",true,"saved"]"#,
            "ok",
        ),
        (br#"["CLOSED","sub","rate-limited"]"#, "closed"),
        (br#"["NOTICE","maintenance"]"#, "notice"),
        (br#"["AUTH","challenge"]"#, "auth"),
    ] {
        let frame = RelayFrame::from_json(bytes, 0, &event_limits, &frame_limits).unwrap();
        assert_eq!(
            match frame {
                RelayFrame::EndOfStoredEvents { .. } => "eose",
                RelayFrame::Ok { .. } => "ok",
                RelayFrame::Closed { .. } => "closed",
                RelayFrame::Notice(_) => "notice",
                RelayFrame::AuthChallenge(_) => "auth",
                RelayFrame::Event { .. } => "event",
            },
            expected
        );
    }
}

#[test]
fn rejects_wrong_shapes_trailing_fields_and_tampered_nested_events() {
    let event_limits = EventLimits::default();
    let frame_limits = FrameLimits::default();
    for bytes in [
        br#"{}"#.as_slice(),
        br#"["EOSE"]"#,
        br#"["EOSE","sub","trailing"]"#,
        br#"["UNKNOWN","sub"]"#,
        br#"["OK","short",true,"saved"]"#,
    ] {
        assert!(RelayFrame::from_json(bytes, 0, &event_limits, &frame_limits).is_err());
    }

    let mut event = signed_event();
    event.content.push('!');
    let frame = serde_json::to_vec(&("EVENT", "sub", event)).unwrap();
    assert!(matches!(
        RelayFrame::from_json(&frame, 1_700_000_000, &event_limits, &frame_limits),
        Err(FrameError::Event(EventError::IdMismatch))
    ));
}

#[test]
fn rejects_resource_limit_violations_before_use() {
    let event_limits = EventLimits::default();
    let frame_limits = FrameLimits::default();
    assert!(matches!(
        RelayFrame::from_json(
            &vec![b' '; frame_limits.max_frame_bytes + 1],
            0,
            &event_limits,
            &frame_limits
        ),
        Err(FrameError::FrameTooLarge { .. })
    ));
    assert!(matches!(
        ClientFrame::Close {
            subscription_id: "x".repeat(frame_limits.max_subscription_id_bytes + 1)
        }
        .to_json(&frame_limits),
        Err(FrameError::InvalidSubscriptionId)
    ));
    assert!(matches!(
        ClientFrame::Request {
            subscription_id: "sub".into(),
            filters: vec![json!(false)]
        }
        .to_json(&frame_limits),
        Err(FrameError::FilterMustBeObject)
    ));
}
