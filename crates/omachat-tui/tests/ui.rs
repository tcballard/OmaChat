use omachat_proto::ipc::Command;
use omachat_tui::{Conversation, DeliveryState, InputMode, Message, UiModel, parse_input};
use ratatui::{
    Terminal,
    backend::TestBackend,
    buffer::Buffer,
    layout::{Position, Rect},
    style::Color,
    widgets::Widget,
};

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

fn draw(width: u16, height: u16) -> Buffer {
    let mut buffer = Buffer::empty(Rect::new(0, 0, width, height));
    model().render(buffer.area, &mut buffer);
    buffer
}

fn rows(buffer: &Buffer) -> Vec<String> {
    (buffer.area.top()..buffer.area.bottom())
        .map(|y| {
            (buffer.area.left()..buffer.area.right())
                .filter_map(|x| buffer.cell(Position::new(x, y)))
                .map(|cell| cell.symbol().to_owned())
                .collect()
        })
        .collect()
}

/// The sixteen ANSI colours are the whole permitted palette: no truecolor and
/// no extended-palette index may reach the terminal.
fn is_ansi16(color: Color) -> bool {
    !matches!(color, Color::Rgb(..)) && !matches!(color, Color::Indexed(index) if index > 15)
}

#[test]
fn eighty_by_twenty_four_and_narrow_layouts_are_bounded_ansi16() {
    for (width, height) in [(80, 24), (24, 10)] {
        let buffer = draw(width, height);
        let rendered = rows(&buffer);
        assert_eq!(rendered.len(), usize::from(height));
        assert!(
            rendered
                .iter()
                .all(|row| row.chars().count() == usize::from(width))
        );
        for y in buffer.area.top()..buffer.area.bottom() {
            for x in buffer.area.left()..buffer.area.right() {
                let cell = buffer.cell(Position::new(x, y)).expect("cell inside area");
                assert!(
                    is_ansi16(cell.fg) && is_ansi16(cell.bg),
                    "cell ({x},{y}) leaves the ANSI-16 palette: fg={:?} bg={:?}",
                    cell.fg,
                    cell.bg
                );
            }
        }
        assert!(rendered.iter().any(|row| row.contains("#gcpvj")));
        assert!(rendered.iter().any(|row| row.contains('○')));
    }
}

#[test]
fn wide_layout_shows_the_sidebar_and_narrow_layout_drops_it() {
    let wide = rows(&draw(80, 24));
    assert!(wide.iter().any(|row| row.contains('│')));
    assert!(wide.iter().any(|row| row.contains("> #gcpvj (2)")));
    assert!(wide.iter().any(|row| row.contains("Conversations")));

    let narrow = rows(&draw(24, 10));
    assert!(narrow.iter().all(|row| !row.contains('│')));
    assert!(narrow.iter().all(|row| !row.contains("Conversations")));
}

#[test]
fn status_bar_reports_mode_and_prompt_holds_input() {
    let mut model = model();
    model.input_mode = InputMode::Scroll;
    model.input = "typing".into();
    let mut buffer = Buffer::empty(Rect::new(0, 0, 80, 24));
    (&model).render(buffer.area, &mut buffer);
    let rendered = rows(&buffer);
    assert!(
        rendered
            .iter()
            .any(|row| row.contains("connected | Scroll"))
    );
    assert!(
        rendered
            .last()
            .is_some_and(|row| row.starts_with("> typing"))
    );
}

/// Cooked-mode input echoes at the caret, so the caret has to sit on the prompt
/// row after the composed text or typing lands in the status bar.
#[test]
fn prompt_cursor_tracks_composed_input_on_the_last_row() {
    let mut model = model();
    let area = Rect::new(0, 0, 80, 24);
    assert_eq!(model.prompt_cursor(area), Position::new(2, 23));

    model.input = "/rooms".into();
    assert_eq!(model.prompt_cursor(area), Position::new(8, 23));

    model.input = "x".repeat(200);
    assert_eq!(model.prompt_cursor(area), Position::new(79, 23));

    let narrow = Rect::new(0, 0, 24, 10);
    model.input = "hi".into();
    assert_eq!(model.prompt_cursor(narrow), Position::new(4, 9));
}

#[test]
fn terminal_draw_renders_the_model_through_a_backend() {
    let mut terminal = Terminal::new(TestBackend::new(80, 24)).expect("test backend terminal");
    terminal
        .draw(|frame| frame.render_widget(&model(), frame.area()))
        .expect("draw succeeds");
    let rendered = rows(terminal.backend().buffer());
    assert_eq!(rendered.len(), 24);
    assert!(rendered.iter().any(|row| row.contains("#gcpvj")));
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
