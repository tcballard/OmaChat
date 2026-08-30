# OC-007 key-storage and user-service lifecycle probe

Status: portable file-mode proof complete; Omarchy v4.0.1 lifecycle capture pending

The probe exercises only synthetic bytes. It checks the default Secret Service
collection without prompting to unlock it, or a mode-0600 file fallback. The
selected provider is written once to a mode-0600 marker. Subsequent `auto` runs
reuse it. If Secret Service was selected and later becomes locked or
unavailable, the run fails; it does not create a file key or new identity.

```sh
cargo build -p omachat-store --example storage_lifecycle_probe --release
install -Dm755 target/release/examples/storage_lifecycle_probe \
  ~/.local/libexec/omachat-g0-storage-probe
install -Dm644 conformance/probes/systemd/omachat-g0-lifecycle.service \
  ~/.config/systemd/user/omachat-g0-lifecycle.service
systemctl --user daemon-reload
```

`RuntimeDirectory=omachat` creates a private runtime directory and the probe
binds `probe.sock` below it with mode 0600. `StateDirectory=omachat-g0` creates
the state root. Neither the unit nor package instructions enable linger.

```sh
target/release/examples/storage_lifecycle_probe \
  --state-dir ~/.local/state/omachat-g0 --status
printf 'status\n' | socat - UNIX-CONNECT:"$XDG_RUNTIME_DIR/omachat/probe.sock"
```

| Scenario | Required observation |
|---|---|
| Graphical login, unlocked keyring | Secret Service selected or existing file choice retained; round trip passes |
| Keyring locked after Secret Service selection | Fails closed; marker stays `secret-service`; no fallback appears |
| Logout without linger | User manager and probe stop; runtime socket disappears |
| Logout with owner-enabled linger | Probe remains active; socket stays 0600 |
| Boot before keyring unlock | Existing Secret Service selection reports unavailable and never falls back |
| Service restart | State directory remains 0700; runtime directory is recreated 0700; socket is 0600 |

Enable or disable linger only as an explicit owner action during the test:

```sh
loginctl enable-linger "$USER"
loginctl disable-linger "$USER"
```

The probe is not a production encrypted-record provider and stores no identity.
