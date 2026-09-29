# OmaChat Desktop — development preview

<img src="https://raw.githubusercontent.com/tcballard/omarchy-badges/75975e5b5bf75e7ede3764bcd2950046f7abfe2c/badges/v1/omarchy-app.svg" alt="Omarchy App" height="20">

A standalone, mouse-friendly conversation window over OmaChat's Rust daemon.
This is the first desktop slice, stacked on the IPC v2 / live TUI trial in
[PR #230](https://github.com/tcballard/OmaChat/pull/230). It is not a release or
an official Omarchy default. No exact Omarchy version has been tested for this
desktop client yet. PR #230's XPS evidence applies to its daemon/TUI only.

## What works in this slice

- Conversation sidebar and local conversation filter; direct conversations
  opened with an npub, nprofile, nostr: contact link, or hexadecimal public key.
- Live recent messages and delivery updates via the daemon's subscription.
- Multiline, selectable plain text; Enter sends, Shift+Enter inserts a newline.
- Per-conversation drafts saved through the daemon’s sealed store when it
  advertises draft support. Switching chats while a send is pending cannot
  clear another chat’s draft. Conflicts preserve local text until you choose.
- Explicit queued / relay-stored / failed states. Relay storage is not proof
  of recipient delivery or reading. No typing indicators or read receipts.
- Reconnect with a 1–30 second backoff and a fresh recent-history snapshot.
  A send whose outcome is unknown requires the user to check before resending.
- Joining a room on an already configured NIP-29 relay. Admission remains relay
  policy; NIP-29 room messages are **not end-to-end encrypted DMs**.
- Identity/connection panel; Ctrl+N for a DM and Ctrl+K for conversation search.
- Narrow-window layout, visible keyboard focus, theme colors read at launch
  from `~/.config/omarchy/current/theme/colors.toml`, with a fallback palette.

The theme reader respects `XDG_CONFIG_HOME`, reads at most 16 KiB, accepts only
hexadecimal background/foreground/accent values, and does not execute theme
code. Relaunch after a theme change. No third-party source/artwork is bundled;
the existing 0BSD license covers these files. Qt/Quickshell and Python are
separately installed runtimes under their respective licenses. PySide6 is used
only for offscreen development tests, not shipped by the launcher.

## Run from this branch on Omarchy

Requires the existing Rust 1.98.0 toolchain, Python 3.11+, Quickshell, and its
Qt Quick Controls/Layouts modules. Quickshell runs as a separate application;
this does not install a shell plugin or restart the Omarchy shell.

```sh
cargo build --workspace --bins --release --locked
# Start your configured daemon in a separate terminal if it is not running:
./target/release/omachatd
# Launch the desktop window:
sh desktop/omachat-desktop
```

The daemon owns first-run identity creation and storage. The desktop does not
claim a handle or create/import keys. Read [daemon installation and storage
guidance](../docs/installation.md) before selecting your storage provider.

For a separately located trial socket:

```sh
OMACHAT_SOCKET=/absolute/path/to/ipc.sock sh desktop/omachat-desktop
```

The socket must be owned by the current Unix user with no group/other access.
The adapter also checks the connected peer's UID. This excludes other Unix
accounts, not malicious software already running as your account.

### Configure messaging

Open **Set up messaging** in the sidebar. Load the configuration used by your
daemon, enter NIP-17 inbox and optional NIP-29 room relay URLs, then save. The
editor creates a private backup of an existing file and preserves unrelated
settings. A changed file is rejected until reloaded. It does not contact relays,
create accounts, modify key storage, or restart services. URLs alone do not
prove a relay implements the required protocol.

The default path follows absolute `XDG_CONFIG_HOME` or `~/.config`. Set
`OMACHAT_CONFIG=/absolute/path/config.json` when launching the desktop, or choose
the path in the dialog, if the daemon uses `--config`. The UI cannot infer a
custom daemon path. Confirm it before saving. Configuration operations and
unapplied settings also block normal window close.

Restart the daemon after saving (instructions below). For a source-run daemon,
stop it and run `./target/release/omachatd --config /absolute/path/config.json`.
Backups are named `config.json.backup-<random>` beside the file, mode 0600. To
roll back, stop the daemon, restore the desired backup, and restart. Backups may
contain existing sensitive settings; preserve or remove them intentionally.
Uninstalling the desktop does not remove configuration or backups.

Manual configuration remains supported:

The daemon reads `$XDG_CONFIG_HOME/omachat/config.json`, normally
`~/.config/omachat/config.json`. Add the relevant fields to your existing
configuration; **do not overwrite an existing config with this illustration**:

```json
{
  "dm_relays": ["wss://your-nip17-relay.example"],
  "rooms": { "relays": ["wss://your-nip29-relay.example"] }
}
```

Those addresses are placeholders, not working hosted services. Use a relay
you operate or are authorized to use with the required Nostr features.
An authenticated NIP-17 inbox is required by this desktop's DM send flow;
it refuses the older private-envelope fallback when `dm_relay_count` is zero.
Configure NIP-29 room relays independently; OmaChat's Grain bootstrap does not
provide NIP-29. Restart the daemon after relay changes. Existing package users
can use `systemctl --user restart omachatd.service`; a source-run daemon can be
stopped with Ctrl+C and restarted with the same arguments.

Connect two configured clients, open **My identity & connection** on each,
copy contact links, and paste them into **New message**. A connected green marker
means the *local daemon* is connected, not that a remote relay or peer is online.

### Stop, remove, and preserve data

Close the window to exit the desktop and its owned adapter. The daemon keeps
running. No install step, autostart, service, desktop setting, or binding is
changed by the launcher. Remove this checkout (or its `desktop/` directory) to
remove the preview. Daemon identity, sealed history, and outbox are untouched.
Normal window close checks every conversation for unsaved drafts, conflicts,
pending sends and unknown send outcomes. Choose **Keep editing**, **Save and
close**, or explicitly **Close anyway**. Saving waits up to ten seconds; failure
keeps the window and text intact. Autosave runs every 600 ms while connected. Older daemons retain session-only drafts.
Saved drafts remain in the daemon’s sealed store; no plaintext disk cache is created.
A different daemon identity on reconnect clears the previous session's view
and drafts so they cannot accidentally be sent as another identity.

## Scope and remaining work

This is a recent-history client, not an archive: PR #230 retains at most 128
messages / 32 KiB / 24 hours in its sealed UI cache. The presentation bounds
each conversation to 128 messages and the session to 128 conversations.
There is no older-history paging, attachment flow,
notification service, profile search, account recovery UI,
room creation/moderation UI, or deployment wizard yet. Global handle claims,
multi-device human identity, and agent coordination must not be inferred from
this desktop UI. See the [product roadmap](../docs/desktop-roadmap.md).

## Tests

```sh
python3 -m unittest discover -s desktop/tests -p 'test_bridge.py' -v
node desktop/tests/test_state.js
node desktop/tests/test_contact.js
node desktop/tests/test_drafts.js
python3 -m venv /tmp/omachat-qt-tests
/tmp/omachat-qt-tests/bin/pip install PySide6==6.8.3
QT_QPA_PLATFORM=offscreen /tmp/omachat-qt-tests/bin/python -m unittest discover -s desktop/tests -p 'test_view.py' -v
sh -n desktop/omachat-desktop
```

The bridge suite deliberately fails if the environment denies Unix sockets.
The Qt suite loads the **production ChatView** with an explicitly fake backend;
it proves UI behavior, not a live daemon or a Quickshell launch. The CI job runs
all three suites. Runtime evidence and gaps are recorded in
[desktop evidence](../docs/desktop-evidence.md).

## Contact links

NIP-19 checksum and canonical padding are checked before opening a conversation.
NIP-21 `nostr:` links accept public npub/nprofile identifiers only. Private nsec
keys, event links, malformed/duplicate profile keys and mixed-case encodings are
rejected. Unknown profile metadata is ignored. Relay hints are not followed or
added to configuration; links do not cause network requests. IPC continues to
use hexadecimal keys. A checksum identifies a well-formed key, not a trusted
person or a verified handle. The identity panel provides a copyable public link.

## Saved draft recovery

The draft status distinguishes loading, saving, saved, offline, storage errors,
and conflicts. Drafts are local to this daemon, not synchronized between devices.
A recovered draft must be reviewed before sending: a crash could have happened
after sending but before clearing its saved copy. Check recent messages first.
After a successful send the desktop requests an empty draft with the last known
revision. Another client’s newer draft cannot be silently deleted.

On conflict, the saved version is shown separately. **Keep my text** attempts a
revision-checked replacement; **Use saved text** replaces the composer. Another
intervening edit causes another conflict. Storage failures preserve your local
text and offer recovery retry. Draft bodies are fetched only for opened chats;
the startup list contains metadata only. See [storage limits and protocol](../docs/draft-storage.md).

The close guard handles normal Qt window-close requests, including compositor
close shortcuts. Forced termination, power loss, and runtime hot reload can still
lose unsaved/offline edits. A live Quickshell/reboot test is required before release.
