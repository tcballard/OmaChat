# OmaChat desktop

A Quickshell client for the local `omachatd` daemon and one hosted server.
Run `cargo build --workspace --bins`, start the daemon with a hosted configuration,
and launch `desktop/omachat-desktop`. Quickshell, Python 3 and a Wayland session are required.
Set `OMACHAT_SOCKET` for a non-default IPC socket and `OMACHAT_CONFIG` for a non-default config.

Use **Set up messaging** to enter the server URL and its public key, obtained from the operator.
Saving backs up an existing file, replaces retired transport settings, and requires a daemon restart.
Use **My identity** to claim a handle, **New message** to open an @handle, and **Workspaces**
to create workspaces/channels or add members (owners only).

Messages are stored by the server; delivered/read labels reflect another member's receipt.
The operator can read messages. This is not end-to-end encryption.
Drafts and recent history are sealed by the daemon. Unknown send outcomes require review before retry.

Nostr contact links, relays and rooms have been removed. Existing hosted device credentials remain valid.
See [the delivery plan](../docs/hosted-server-plan.md) for deployment and security-review work.

Tests: `node desktop/tests/test_state.js`, `node desktop/tests/test_drafts.js`,
`node desktop/tests/test_hosted.js`, and `QT_QPA_PLATFORM=offscreen python -m unittest discover -s desktop/tests`.
The Qt tests require PySide6. `python scripts/test-hosted-desktop.py` drives two real daemons.
