use futures_util::{SinkExt, StreamExt};
use omachat_nostr::{
    event::SignedEvent,
    mailbox::{
        COMPATIBILITY_LOOKBACK_SECONDS, MailboxConfig, MailboxReceive, PrivateMailbox,
        PrivatePublishResult, PrivateRelayProfile, publish_gift_wrap,
    },
    pool::{RelayPool, RelayPoolConfig},
    relay::{RelayConfig, RelayNotification, RelayRoute},
};
use serde::Deserialize;
use serde_json::{Value, json};
use std::{fs, path::PathBuf, time::Duration};
use tokio::net::{TcpListener, TcpStream};
use tokio_tungstenite::{WebSocketStream, accept_async, tungstenite::Message};

#[derive(Deserialize)]
struct Inputs {
    recipient_private_key_hex: String,
}

#[derive(Deserialize)]
struct Outputs {
    authenticated_open: AuthenticatedOpen,
    gift_wrap_event: SignedEvent,
}

#[derive(Deserialize)]
struct AuthenticatedOpen {
    content: String,
    sender_pubkey: String,
    true_created_at: u64,
}

fn workspace_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(|path| path.parent())
        .expect("crate must be in workspace/crates")
        .to_owned()
}

fn load<T: for<'de> Deserialize<'de>>(fixture: &str, file: &str) -> T {
    serde_json::from_slice(
        &fs::read(
            workspace_root()
                .join("conformance/fixtures")
                .join(fixture)
                .join(file),
        )
        .unwrap(),
    )
    .unwrap()
}

fn hex_array<const N: usize>(value: &str) -> [u8; N] {
    let mut bytes = [0; N];
    hex::decode_to_slice(value, &mut bytes).unwrap();
    bytes
}

#[test]
fn pinned_profile_is_the_deduplicated_mobile_union() {
    let profile = PrivateRelayProfile::pinned();
    assert_eq!(
        profile.urls,
        [
            "wss://relay.damus.io",
            "wss://nos.lol",
            "wss://relay.primal.net",
            "wss://offchain.pub",
            "wss://nostr21.com",
        ]
    );
}

#[test]
fn authenticates_both_released_shapes_and_deduplicates_after_open() {
    for fixture in [
        "swift-nostr-private-envelope-tagless-v1",
        "swift-nostr-private-envelope-android-shape-v1",
    ] {
        let input: Inputs = load(fixture, "inputs.json");
        let output: Outputs = load(fixture, "outputs.json");
        let recipient_secret = hex_array(&input.recipient_private_key_hex);
        let now = output.gift_wrap_event.created_at + 48 * 60 * 60;
        let mut mailbox = PrivateMailbox::new(MailboxConfig::default()).unwrap();

        assert_eq!(
            mailbox
                .receive(&output.gift_wrap_event, &recipient_secret, now)
                .unwrap(),
            MailboxReceive::Message(omachat_nostr::mailbox::PrivateMessage {
                metadata: omachat_nostr::mailbox::PrivateMessageMetadata {
                    gift_wrap_id: output.gift_wrap_event.id.clone(),
                    sender_pubkey: output.authenticated_open.sender_pubkey,
                    true_created_at: output.authenticated_open.true_created_at,
                },
                content: output.authenticated_open.content,
            })
        );
        assert_eq!(
            mailbox
                .receive(&output.gift_wrap_event, &recipient_secret, now + 1)
                .unwrap(),
            MailboxReceive::Duplicate {
                gift_wrap_id: output.gift_wrap_event.id,
            }
        );
    }
}

#[test]
fn blocked_content_is_hidden_only_after_authenticated_open() {
    let fixture = "swift-nostr-private-envelope-tagless-v1";
    let input: Inputs = load(fixture, "inputs.json");
    let output: Outputs = load(fixture, "outputs.json");
    let recipient_secret = hex_array(&input.recipient_private_key_hex);
    let mut mailbox = PrivateMailbox::new(MailboxConfig::default()).unwrap();
    mailbox
        .block_sender(&output.authenticated_open.sender_pubkey)
        .unwrap();

    let received = mailbox
        .receive(
            &output.gift_wrap_event,
            &recipient_secret,
            output.gift_wrap_event.created_at,
        )
        .unwrap();
    let MailboxReceive::Blocked(metadata) = received else {
        panic!("blocked sender content must not be returned")
    };
    assert_eq!(
        metadata.sender_pubkey,
        output.authenticated_open.sender_pubkey
    );

    let mut tampered = output.gift_wrap_event.clone();
    tampered.content.push('!');
    let mut fresh = PrivateMailbox::new(MailboxConfig::default()).unwrap();
    assert!(
        fresh
            .receive(
                &tampered,
                &recipient_secret,
                output.gift_wrap_event.created_at
            )
            .is_err()
    );
    assert!(matches!(
        fresh
            .receive(
                &output.gift_wrap_event,
                &recipient_secret,
                output.gift_wrap_event.created_at
            )
            .unwrap(),
        MailboxReceive::Message(_)
    ));
}

fn relay_config(address: std::net::SocketAddr) -> RelayConfig {
    let mut config = RelayConfig::new(format!("ws://{address}/"), RelayRoute::Direct);
    config.ping_interval = Duration::from_secs(5);
    config.idle_timeout = Duration::from_secs(15);
    config.response_timeout = Duration::from_millis(500);
    config.reconnect_initial_delay = Duration::from_millis(10);
    config.reconnect_max_delay = Duration::from_millis(20);
    config
}

async fn next_json(socket: &mut WebSocketStream<TcpStream>) -> Value {
    loop {
        match socket.next().await.unwrap().unwrap() {
            Message::Text(text) => return serde_json::from_str(&text).unwrap(),
            Message::Ping(payload) => socket.send(Message::Pong(payload)).await.unwrap(),
            other => panic!("unexpected mailbox client message: {other:?}"),
        }
    }
}

async fn acknowledgement_server(listener: TcpListener, accepted: bool) {
    let (stream, _) = listener.accept().await.unwrap();
    let mut socket = accept_async(stream).await.unwrap();
    let publish = next_json(&mut socket).await;
    socket
        .send(Message::Text(
            json!(["OK", publish[1]["id"], accepted, "mailbox-policy"])
                .to_string()
                .into(),
        ))
        .await
        .unwrap();
    while let Some(Ok(message)) = socket.next().await {
        if matches!(message, Message::Close(_)) {
            break;
        }
    }
}

async fn wait_connected(pool: &mut RelayPool, count: usize) {
    let mut connected = 0;
    tokio::time::timeout(Duration::from_secs(2), async {
        while connected < count {
            if matches!(
                pool.next_notification().await.unwrap().notification,
                RelayNotification::Connected
            ) {
                connected += 1;
            }
        }
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn private_publish_never_reports_storage_below_the_pool_threshold() {
    let output: Outputs = load("swift-nostr-private-envelope-tagless-v1", "outputs.json");
    let first = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let second = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let configs = vec![
        relay_config(first.local_addr().unwrap()),
        relay_config(second.local_addr().unwrap()),
    ];
    let first_server = tokio::spawn(acknowledgement_server(first, true));
    let second_server = tokio::spawn(acknowledgement_server(second, false));
    let mut pool = RelayPool::spawn(
        configs,
        RelayPoolConfig {
            acknowledgement_threshold: 2,
            ..RelayPoolConfig::default()
        },
    )
    .unwrap();
    wait_connected(&mut pool, 2).await;

    assert_eq!(
        publish_gift_wrap(&pool, output.gift_wrap_event.clone()).await,
        PrivatePublishResult::NotStored {
            gift_wrap_id: output.gift_wrap_event.id,
            accepted: 1,
            required: 2,
            attempted: 2,
        }
    );
    for outcome in pool.shutdown().await {
        outcome.unwrap();
    }
    first_server.await.unwrap();
    second_server.await.unwrap();
}

#[tokio::test]
async fn offline_event_is_delivered_after_reconnect_across_the_compatibility_lookback() {
    let fixture = "swift-nostr-private-envelope-tagless-v1";
    let input: Inputs = load(fixture, "inputs.json");
    let output: Outputs = load(fixture, "outputs.json");
    let gift_wrap = output.gift_wrap_event;
    let recipient_secret = hex_array(&input.recipient_private_key_hex);
    let recipient_pubkey = gift_wrap.tags[0][1].clone();
    let now = gift_wrap.created_at + 48 * 60 * 60;
    let mut mailbox = PrivateMailbox::new(MailboxConfig::default()).unwrap();
    let filter = mailbox.subscription_filter(&recipient_pubkey, now).unwrap();
    assert_eq!(
        filter["since"],
        now.saturating_sub(COMPATIBILITY_LOOKBACK_SECONDS)
    );
    assert!(gift_wrap.created_at >= filter["since"].as_u64().unwrap());

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let config = relay_config(listener.local_addr().unwrap());
    let expected_filter = filter.clone();
    let stored = gift_wrap.clone();
    let server = tokio::spawn(async move {
        let (stream, _) = listener.accept().await.unwrap();
        let mut socket = accept_async(stream).await.unwrap();
        let request = next_json(&mut socket).await;
        assert_eq!(request, json!(["REQ", "private-mailbox", expected_filter]));
        socket
            .send(Message::Text(
                json!(["EVENT", "private-mailbox", stored])
                    .to_string()
                    .into(),
            ))
            .await
            .unwrap();
        socket
            .send(Message::Text(
                json!(["EOSE", "private-mailbox"]).to_string().into(),
            ))
            .await
            .unwrap();
        while let Some(Ok(message)) = socket.next().await {
            if matches!(message, Message::Close(_)) {
                break;
            }
        }
    });

    let mut pool = RelayPool::spawn(vec![config], RelayPoolConfig::default()).unwrap();
    wait_connected(&mut pool, 1).await;
    assert!(
        pool.subscribe("private-mailbox".into(), vec![filter])
            .await
            .iter()
            .all(Result::is_ok)
    );
    let event = tokio::time::timeout(Duration::from_secs(2), async {
        loop {
            if let RelayNotification::Event { event, .. } =
                pool.next_notification().await.unwrap().notification
            {
                break event;
            }
        }
    })
    .await
    .unwrap();
    assert!(matches!(
        mailbox.receive(&event, &recipient_secret, now).unwrap(),
        MailboxReceive::Message(_)
    ));

    for outcome in pool.shutdown().await {
        outcome.unwrap();
    }
    server.await.unwrap();
}
