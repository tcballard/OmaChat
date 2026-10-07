# Development installation

Build with Rust 1.98.0 using `cargo build --workspace --bins`. Install the client
binaries `omachatd`, `omachat`, and `omachat-ctl` together; they use IPC v3.
Quickshell and Python 3 are required for `desktop/omachat-desktop`.
The preview is not a published release or an official Omarchy default.

Place configuration at `$XDG_CONFIG_HOME/omachat/config.json` (normally
`~/.config/omachat/config.json`), private to your user:

```json
{
  "storage_provider": "auto",
  "hosted": {
    "url": "wss://chat.example",
    "pinned_server_public_key": "REPLACE_WITH_OPERATOR_SUPPLIED_64_HEX_CHARACTER_KEY",
    "display_name": "Alice"
  }
}
```

The placeholder is intentionally invalid. Obtain the pin from the operator;
never derive trust from an unverified network response. Add `invite_code` if required.
The operator can read messages. See ops/server/README.md for hosting instructions.

Start `omachatd` in a user session with `XDG_RUNTIME_DIR` set. The default socket is
`$XDG_RUNTIME_DIR/omachat/omachat.sock`. Use `--config`, `--state`, and `--socket`
for isolated testing, and `--file-key` when Secret Service is unavailable.
The supplied systemd user unit is optional; packaging does not enable it automatically.

Desktop **Set up messaging** edits this configuration with a private backup,
revision checks and atomic replacement. Restart the daemon after changes.
Old Nostr settings are rejected and must be replaced. Existing hosted signing keys,
accounts and hosted drafts survive the upgrade; retired sealed records are not used.

`omachat-ctl hosted-claim-handle alice` claims a server-scoped handle.
`omachat-ctl hosted-open-dm bob` opens a direct conversation. Use its returned
`hosted:` identifier with `send` or `hosted-history`.
The desktop offers the same actions, plus workspace/channel administration.
