# Development installation

Build with Rust 1.98.0 using `cargo build --workspace --bins`. Install the client
binaries `omachatd`, `omachat`, and `omachat-ctl` together; they use IPC v4.
The preview is not a published release or an official Omarchy default.

`omachat` is the terminal client. `sh desktop/omachat-desktop` is the
Quickshell window. Both need `omachatd`. The archived Slack-style product is
on branch `hosted-archive` at commit `825cf07123`.

Place configuration at `$XDG_CONFIG_HOME/omachat/config.json` (normally
`~/.config/omachat/config.json`), private to your user:

```json
{
  "storage_provider": "auto",
  "dm_relays": ["wss://relay.example"],
  "hosted": {
    "url": "wss://chat.example",
    "pinned_server_public_key": "REPLACE_WITH_OPERATOR_SUPPLIED_64_HEX_CHARACTER_KEY",
    "display_name": "Alice"
  }
}
```

The placeholder is intentionally invalid. Obtain the pin from the operator;
never derive trust from an unverified network response. Omit `hosted` to run
the daemon with only the local device credential. `dm_relays` is optional
until you send a message; use relays you are allowed to use. The server stores
handles, not messages. See ops/server/README.md for hosting instructions.

Start `omachatd` in a user session with `XDG_RUNTIME_DIR` set. The default socket is
`$XDG_RUNTIME_DIR/omachat/omachat.sock`. Use `--config`, `--state`, and `--socket`
for isolated testing, and `--file-key` when Secret Service is unavailable.
The supplied systemd user unit is optional; packaging does not enable it automatically.

`omachat-ctl hosted-claim-handle alice` claims a server-scoped handle once the
daemon is connected. `omachat-ctl hosted-resolve-handle alice` looks one up.
`omachat-ctl identity generate` creates a sealed Nostr key, `identity show`
prints the `npub`, and `identity export` prints the `nsec`. `identity bind`
attaches that key to the claimed handle. `identity import nsec1...` loads an
existing key and refuses to replace one that is already stored.
`dm_relays` is the Nostr relay list. Other retired chat settings are rejected.
Existing device signing keys remain valid. A chat database from the archived
server is not opened by this binary. Opening `omachat` or the desktop creates
a sealed Nostr key if you do not have one. `identity show` does not.
