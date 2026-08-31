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
