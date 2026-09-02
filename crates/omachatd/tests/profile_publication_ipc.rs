use futures_util::{SinkExt, StreamExt};
use omachat_nostr::{event::SignedEvent, profile_metadata::PROFILE_METADATA_KIND};
use omachat_proto::ipc::{Command, ErrorCode, Request, ResponseOutcome, VERSION};
use omachatd::{
    DaemonConfig, DaemonCore, EventHub, ProfilePublicationConfig, RequestHandler,
    StorageProviderConfig,
};
use serde_json::json;
use tempfile::tempdir;
use tokio::net::TcpListener;
use tokio::sync::oneshot;
use tokio_tungstenite::{accept_async, tungstenite::Message};

#[tokio::test]
async fn ipc_publishes_a_device_principal_profile() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let relay_url = format!("ws://{}/", listener.local_addr().unwrap());
    let relay = tokio::spawn(async move {
        let (stream, _) = listener.accept().await.unwrap();
        let mut socket = accept_async(stream).await.unwrap();
        let event = loop {
            match socket.next().await.unwrap().unwrap() {
                Message::Text(text) => {
                    let frame: serde_json::Value = serde_json::from_str(&text).unwrap();
                    if frame[0] == "EVENT" {
                        break serde_json::from_value::<SignedEvent>(frame[1].clone()).unwrap();
                    }
                }
                Message::Ping(payload) => socket.send(Message::Pong(payload)).await.unwrap(),
                other => panic!("unexpected profile frame: {other:?}"),
            }
        };
        socket
            .send(Message::Text(
                json!(["OK", event.id, true, "stored"]).to_string().into(),
            ))
            .await
            .unwrap();
        while let Some(Ok(message)) = socket.next().await {
            if matches!(message, Message::Close(_)) {
                break;
            }
        }
        event
    });
    let state = tempdir().unwrap();
    let core = DaemonCore::open(
        state.path(),
        DaemonConfig {
            storage_provider: StorageProviderConfig::File,
            account_handle: Some("tom".into()),
            account_display_name: Some("Tom Ballard".into()),
            profile_publication: Some(ProfilePublicationConfig {
                relays: vec![relay_url],
                required_acknowledgements: 1,
            }),
            ..DaemonConfig::default()
        },
        EventHub::default(),
    )
    .await
    .unwrap();
    let outcome = core
        .handle(Request {
            version: VERSION,
            id: "publish-profile".into(),
            command: Command::PublishProfile,
        })
        .await;
    let ResponseOutcome::Ok { result } = outcome else {
        panic!("profile publication failed");
    };
    assert_eq!(result["publication_status"], "complete");
    assert_eq!(result["publication_source"], "new");
    assert_eq!(result["acknowledged_relays"], 1);
    assert_eq!(result["required_acknowledgements"], 1);
    assert_eq!(result["global_handle_verified_by_profile"], false);
    assert_eq!(result["principal_type"], "device");
    assert_eq!(result["profile_subject"], "device_nostr_key");
    assert_eq!(result["account_root_authorship"], false);
    core.prepare_for_shutdown().await;
    let event = relay.await.unwrap();
    assert_eq!(event.kind, PROFILE_METADATA_KIND);
    assert_eq!(event.pubkey, result["public_key"]);
    let metadata: serde_json::Value = serde_json::from_str(&event.content).unwrap();
    assert_eq!(metadata["name"], "tom");
    assert_eq!(metadata["display_name"], "Tom Ballard");
}

#[tokio::test]
async fn profile_publication_is_truthfully_unavailable_without_config() {
    let state = tempdir().unwrap();
    let core = DaemonCore::open(
        state.path(),
        DaemonConfig {
            storage_provider: StorageProviderConfig::File,
            ..DaemonConfig::default()
        },
        EventHub::default(),
    )
    .await
    .unwrap();
    let outcome = core
        .handle(Request {
            version: VERSION,
            id: "publish-profile-disabled".into(),
            command: Command::PublishProfile,
        })
        .await;
    assert!(matches!(
        outcome,
        ResponseOutcome::Error { error }
            if error.code == ErrorCode::Unavailable
                && error.message == "profile publication is not configured"
    ));
}

#[tokio::test]
async fn panic_erasure_cancels_profile_publication_before_erasing_keys() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let relay_url = format!("ws://{}/", listener.local_addr().unwrap());
    let (started, publication_started) = oneshot::channel();
    let relay = tokio::spawn(async move {
        let (stream, _) = listener.accept().await.unwrap();
        let mut socket = accept_async(stream).await.unwrap();
        while let Some(Ok(message)) = socket.next().await {
            match message {
                Message::Text(text) => {
                    let frame: serde_json::Value = serde_json::from_str(&text).unwrap();
                    if frame[0] == "EVENT" {
                        let _ = started.send(());
                        while let Some(Ok(message)) = socket.next().await {
                            if matches!(message, Message::Close(_)) {
                                return;
                            }
                        }
                        return;
                    }
                }
                Message::Ping(payload) => socket.send(Message::Pong(payload)).await.unwrap(),
                Message::Close(_) => return,
                _ => {}
            }
        }
    });
    let state = tempdir().unwrap();
    let core = DaemonCore::open(
        state.path(),
        DaemonConfig {
            storage_provider: StorageProviderConfig::File,
            account_handle: Some("tom".into()),
            profile_publication: Some(ProfilePublicationConfig {
                relays: vec![relay_url],
                required_acknowledgements: 1,
            }),
            ..DaemonConfig::default()
        },
        EventHub::default(),
    )
    .await
    .unwrap();
    let publisher = {
        let core = core.clone();
        tokio::spawn(async move {
            core.handle(Request {
                version: VERSION,
                id: "publish-before-panic".into(),
                command: Command::PublishProfile,
            })
            .await
        })
    };
    publication_started.await.unwrap();
    let panic = tokio::time::timeout(
        std::time::Duration::from_secs(2),
        core.handle(Request {
            version: VERSION,
            id: "panic-profile".into(),
            command: Command::Panic {
                confirmation: "ERASE".into(),
            },
        }),
    )
    .await
    .expect("bounded panic cleanup");
    assert!(matches!(
        panic,
        ResponseOutcome::Ok { result } if result["erased"] == true
    ));
    assert!(matches!(
        publisher.await.unwrap(),
        ResponseOutcome::Error { .. }
    ));
    assert!(core.is_panicked());
    relay.await.unwrap();
}
