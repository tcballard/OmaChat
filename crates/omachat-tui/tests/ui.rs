use omachat_proto::ipc::Command;
use omachat_tui::{Conversation, DeliveryState, Message, UiModel, parse_input};

fn model() -> UiModel {
    UiModel {
        conversations: vec![Conversation {
            id: "gcpvj".into(),
            title: "#gcpvj".into(),
            unread: 2,
            messages: vec![
                Message {
                    sender: "alice".into(),
                    text: "hello".into(),
                    outgoing: false,
                    delivery: None,
                },
                Message {
                    sender: "me".into(),
                    text: "queued".into(),
                    outgoing: true,
                    delivery: Some(DeliveryState::Queued),
                },
            ],
        }],
        connected: true,
        status: "connected".into(),
        ..UiModel::default()
    }
}

#[test]
fn eighty_by_twenty_four_and_narrow_layouts_are_bounded_ansi16() {
    for (width, height) in [(80, 24), (24, 10)] {
        let rendered = model().render(width, height);
        assert_eq!(rendered.lines().count(), usize::from(height));
        assert!(!rendered.contains("38;2"));
        assert!(!rendered.contains("48;2"));
        assert!(rendered.contains("#gcpvj"));
        assert!(rendered.contains('○'));
    }
}

#[test]
fn messaging_commands_map_to_daemon_requests() {
    assert!(matches!(
        parse_input("/join GCPVJ", None),
        Ok(Some(Command::Join { geohash })) if geohash == "GCPVJ"
    ));
    assert!(matches!(
        parse_input("hello", Some("gcpvj")),
        Ok(Some(Command::Send { conversation, text }))
            if conversation == "gcpvj" && text == "hello"
    ));
    assert!(parse_input("hello", None).is_err());
}
