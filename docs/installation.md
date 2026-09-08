# Installation and user-service lifecycle

OmaChat has no supported release package yet. The assets below are pre-release
inputs for the Omarchy v4.0.1 clean-install gate.

## User service

OmaChat's local IPC socket is an account-local control boundary, not an
application sandbox. Socket permissions exclude other Unix users, the daemon
rejects any connection whose peer credentials report a different uid, and it
refuses a concurrent instance, but processes already running as the same
account are inside this trust boundary. Destructive commands (`panic`,
`claim-handle`) require a single-use confirmation token that the daemon mints
into its state directory on request and that expires after 120 seconds, so a
blind one-shot write to the socket cannot erase the account; a same-account
process that can read the state directory can still complete that exchange. Run untrusted desktop software
under a separate OS identity or sandbox that cannot access the account's
runtime directory. In particular, do not describe the `0600` socket as
authenticating individual same-user applications.

Room generation anchors occupy a storage domain separate from sealed room
state and detect accidental restoration of only that state. Neither the file
nor Secret Service provider is a hardware or remote monotonic witness against
a malicious process already trusted as the same OS user. Deployments requiring
that stronger adversary model need an independently controlled witness.

After a package installs the binaries and `omachatd.service`:

```sh
systemctl --user enable --now omachatd.service
systemctl --user status omachatd.service
journalctl --user -u omachatd.service
```

The service creates private runtime and state paths. It does not enable linger.
An owner who wants service after logout may explicitly opt in:

```sh
loginctl enable-linger "$USER"
```

Remove that choice with `loginctl disable-linger "$USER"`. Linger does not keep
a sleeping or powered-off machine online. Keyring availability across boot,
login, logout, lock, and linger must still pass OC-007 on the target machine.

Use `omachat-ctl status`, launch `omachat`, and stop with
`systemctl --user disable --now omachatd.service`. No install or removal action
edits Hyprland, Waybar, shell.json, user config, polkit policy, or linger state.

SIGTERM (the normal systemd stop signal) and SIGINT use the same graceful
shutdown path: stop accepting IPC, drain active requests within the bounded
IPC deadline, remove the socket, and shut down the owned services. Neither
signal erases identity or the sealed outbox. Signal handlers are registered
before the IPC socket becomes available; handler-registration errors fail
startup rather than leaving a running daemon without its shutdown handlers.

When launched with `--config`, SIGHUP validates and applies supported hot
changes such as joined geohashes. Malformed/invalid configuration and relay
policy changes requiring restart are rejected with an error in the journal;
the prior active configuration stays in effect. The reload task is stopped
and joined before service teardown. This does not replace the target-host
login/keyring/linger lifecycle checks in OC-007.

The JSON daemon config may set `account_handle` (for example `"@tom"`) and
`account_display_name`. Both are sealed into a root-signed local binding and
survive restart if later omitted from configuration. Until the central registry
is implemented, status deliberately reports a configured handle as
`local-only`; it has not proved global uniqueness. The separate `nickname`
field remains the public, unlinkable geohash-chat nickname and is never filled
from the account handle automatically. Omitting or setting either account field
to JSON `null` preserves its sealed value in this first slice; replacement uses
a new valid value, while clearing/tombstoning belongs to the registry workflow.

For opt-in geographic selection, configure `geo_relays` with `mode` set to
`supplement` or `replace` and an explicit `overrides` list. See
[pinned geo-relay routing](geo-relays.md) for bounds, health fallback, status
diagnostics and restart requirements. Omission preserves fixed `relays` behaviour.

`dm_relays` is an opt-in list of NIP-17 private-inbox relays (`wss://`, or
numeric-loopback `ws://` for local testing). Geochat `relays` use the same URL
rule. An empty list disables that inbox. Every configured relay
must complete NIP-42 authentication for the persisted device Nostr principal
before OmaChat sends its recipient-only kind-1059 subscription. Relay changes
require a daemon restart. This setting is a reachability choice, not protocol
authority, and no production OmaChat relay is implied by the default config.
When this inbox is active, direct `Send` commands create standard NIP-17
kind-14 messages and publish their persistent kind-1059 gift wraps through the
same authenticated relay set. The sealed outbox records the delivery profile so
restart retries never infer protocol semantics from encrypted payloads.

`rooms` is an opt-in object for standard NIP-29 rooms:

```json
"rooms": {
  "relays": ["wss://rooms.example"],
  "anchor_provider": "file",
  "anchor_directory": null
}
```

`rooms.relays` lists room relays (`wss://`, or numeric-loopback `ws://` for
local testing). Each relay is bound to the signing identity its NIP-11
document declares in `self`; the administrative contact `pubkey` is never
treated as a relay identity. Rooms are addressed as
`room:RELAY_PUBKEY:GROUP`, so a URL change with the same key is the same relay
and the same group ID under another key is a different room. Membership is the
relay's policy decision: `join-room` subscribes and sends a kind 9021 request,
and the relay's verdict is reported, never assumed. Room state is sealed per
relay identity and guarded by a generation anchor that must live outside the
daemon state directory; `rooms.anchor_directory` (or `omachatd --anchors`)
overrides the default sibling directory `<state>-anchors`. Restoring the state
directory from backup without the anchors is detected and refused rather than
silently rewinding rooms. Set `anchor_provider` to `secret-service` to keep
generations in the unlocked default Secret Service collection instead. This
selection fails closed when Secret Service is unavailable, locked, duplicated,
or corrupt; `anchor_directory` and `omachatd --anchors` are rejected with that
provider rather than silently ignored. File anchors remain the portable
default. Relay changes require a daemon restart. The default
configuration permits one active URL per relay signing key. If two configured
URLs declare the same `self` key, both are reported as `identity-conflict` and
stopped before they can concurrently reduce or persist that relay's state.
OmaChat bootstrap relay does not implement NIP-29; configure a NIP-29 relay
explicitly.

## Storage provider

Automatic mode prefers Secret Service and otherwise chooses file mode on first
run. The choice is persisted. `omachatd --file-key` explicitly selects file
mode only when compatible with that choice. Back up the state and its master
key together if recovery is intended; losing the key makes sealed records
unrecoverable. See [SECURITY.md](../SECURITY.md) before relying on panic erase.

## Packaging preflight

Arch recipes live under `packaging/arch`. The tagged recipe deliberately fails
until release automation inserts the exact archive SHA-256. The `-git` recipe
is for local testing. Neither is authorized for AUR publication yet.

The optional Quattro widget lives under `packaging/omarchy-quattro`; validate
it with `omarchy plugin validate` on v4.0.1 before enabling. The legacy Waybar
example is separate and is not the Quattro integration.

## Development trial controls and local history

The daemon reads `$XDG_CONFIG_HOME/omachat/config.json` (normally
`~/.config/omachat/config.json`) when present. `--config PATH` overrides it.
Packages do not create or overwrite that file. Relay configuration changes
require a restart. The unit grants write access to both its state directory
and the separate `omachat-anchors` directory used by room rollback checks.

The TUI subscribes to live messages, delivery, presence, conversations and
status. Tab/Shift-Tab selects a conversation; Escape switches compose/scroll
mode, `i` returns to compose, and Page Up/Down scrolls history. `/help` shows
controls. A disconnected client keeps its draft and retries with a 1–30 second
backoff. It never automatically resends a draft after an ambiguous send failure.
Ctrl-C, Ctrl-D and `/detach` leave the daemon running. SIGINT, SIGTERM and the
panic hook restore the terminal, including release builds using panic-abort.

The daemon keeps a sealed local UI cache of at most 128 messages and 32 KiB,
with a 24-hour age limit. Expiry is enforced on load, updates and snapshots;
this is a bounded recent view, not a full-history archive. Reattaching loads
this snapshot and deduplicates live events by message ID. Retry delivery
updates come from the daemon outbox. Panic clears the cache along with the
other sealed state. This local cache does not define relay or backup retention.

IPC v2 separates response correlation from a bounded client event queue.
Overflow or malformed/incompatible input disconnects the client; the TUI
resubscribes and obtains a fresh snapshot. Subscribe responses include
`status` and `messages`; topic filters govern streamed events. A snapshot and
its queued live tail may overlap, so clients must deduplicate by message ID.
