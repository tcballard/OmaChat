# Nostr acceptance gate

The current priority is reliable messaging over existing Nostr relays, followed
by public NIP-05 handles and everyday client polish. An Omacon community relay
is optional infrastructure. Bluetooth mesh remains the lowest priority.

## Run the automated gate

Requirements: the pinned Rust toolchain, Node 22+, npm and Python 3. No public
relay, domain, user credentials or running desktop session is needed. All
identities are disposable. Sockets bind only to loopback and processes use a
private temporary directory that is removed on exit.

```sh
cargo test -p omachatd --test nostr_dm --locked
cargo build --workspace --bins --locked
npm install --prefix scripts/e2e --ignore-scripts --no-audit --no-fund --package-lock=false
node scripts/e2e/run.mjs
python3 -m unittest discover -s scripts/tests -v
python3 -m unittest discover -s desktop/tests -v
node desktop/tests/test_state.js
```

`OMACHAT_BIN_DIR` can point at a different directory of freshly built binaries.
The npm dependencies and their crypto transitive versions are pinned in
`scripts/e2e/package.json`. They are test-only and are not installed with OmaChat.

The Rust integration test connects real daemon cores to the real handle server,
claims and signs bindings for two identities, resolves their NIP-05 names through
the server, exchanges DMs addressed by those names, and rejects an unbound name.
It uses the existing numeric-loopback resolver test hook; production clients
still require HTTPS.

The process gate runs the actual `omachat-serverd`, two `omachatd` processes,
`omachat-ctl`, the terminal executable and the desktop's Python IPC adapter. It
checks handle JSON/CORS, bidirectional messages, rejected sends, recipient offline
delivery, daemon restart, identity/contact/history persistence, relay reconnect,
and replay deduplication. Its in-memory relay verifies incoming event signatures.

An independent `nostr-tools` 2.25.2 peer uses a WebSocket connection to the same
relay to decrypt OmaChat messages and publish messages that OmaChat decrypts.
Its key is also imported/exported through OmaChat, verifying unchanged identity.
Ordinary captured process output is checked for that private identity; the
explicit export response is consumed privately.

## Interactive desktop and public deployment checks

The process gate covers the real desktop adapter, not rendered Quickshell
controls. On Omarchy, launch `sh desktop/omachat-desktop` with the same daemon
as the terminal, then check:

- Select a contact, type a message and send. The draft clears after success and
  the message says it was accepted by a relay.
- Disconnect the daemon or reject a send. The draft stays available. An uncertain
  outcome asks you to check the conversation before resending.
- Switch contacts with unsent text. Each desktop conversation retains its draft
  for the life of the window. Drafts are not persisted across app restarts.
- Type more while a send is pending; its acknowledgement must not erase the new
  text. Switch contacts while sending and verify the correct draft is cleared.
- In the terminal, submit a message while disconnected. The composer retains it.

Use the [public domain procedure](../ops/server/README.md#publish-nip-05-on-your-domain)
for DNS, Caddy, key pinning and a check from a separate machine. Local fixtures do
not prove public TLS, relay policy compatibility or the UI of Damus, Primal or
Amethyst. A real-client smoke test on the selected relay remains a release check.
