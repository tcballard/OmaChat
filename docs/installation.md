# Installation and user-service lifecycle

OmaChat has no supported release package yet. The assets below are pre-release
inputs for the Omarchy v4.0.1 clean-install gate.

## User service

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

The JSON daemon config may set `account_handle` (for example `"@tom"`) and
`account_display_name`. Both are sealed into a root-signed local binding and
survive restart if later omitted from configuration. Until the central registry
is implemented, status deliberately reports a configured handle as
`local-only`; it has not proved global uniqueness. The separate `nickname`
field remains the public, unlinkable geohash-chat nickname and is never filled
from the account handle automatically. Omitting or setting either account field
to JSON `null` preserves its sealed value in this first slice; replacement uses
a new valid value, while clearing/tombstoning belongs to the registry workflow.

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
