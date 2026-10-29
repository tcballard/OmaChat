# OmaChat desktop

Quickshell window for Nostr direct messages. It talks to `omachatd` over the
private IPC socket. The window can show and copy your `npub`, claim and bind an
`@handle`, add contacts by `npub1…` or `name@domain`, edit relays, and send
gift-wrapped DMs.

Opening the window calls `chat-prepare`. That seals a `nostr-identity-v1` key
when one is not already stored. The window never displays or exports an `nsec`.
Use `omachat-ctl identity export` for that, and only when you mean to.

```sh
cargo build --workspace --bins --release --locked
./target/release/omachatd
sh desktop/omachat-desktop
```

`OMACHAT_SOCKET` overrides the default `$XDG_RUNTIME_DIR/omachat/omachat.sock`.
The socket must be mode `0600` and owned by you.

Relay URLs are saved in the daemon's sealed state and replace `dm_relays` from
the config file on the next start. Use `wss://` relays you operate or are
allowed to use. Numeric-loopback `ws://` is for tests. Both people need at
least one relay in common. The daemon also publishes the first three `wss://`
URLs as your NIP-17 inbox list (kind 10050).

Hosted workspaces, channels, and NIP-29 rooms are not in this window. Claim and
bind still use the handle server when `hosted` is configured.

```sh
python3 -m unittest discover -s desktop/tests -p 'test_*.py' -v
node desktop/tests/test_contact.js
node desktop/tests/test_state.js
sh -n desktop/omachat-desktop
```
