# Hosted server operations profile

Deployment shape for `omachat-serverd`: the server listens on loopback and
refuses anything else; Caddy owns the public `wss://` endpoint and its
certificate. This directory is a profile, not evidence of a deployment.

## Files

- `Caddyfile`: TLS termination and WebSocket proxying to `127.0.0.1:7448`.
- `omachat-serverd.service`: hardened systemd unit running as a dedicated
  user with an owner-only state directory.

## First start

```sh
sudo useradd --system --home /var/lib/omachat-server --shell /usr/sbin/nologin omachat-server
sudo install -m 0755 target/release/omachat-serverd /usr/local/bin/omachat-serverd
sudo install -d -m 0750 -o root -g omachat-server /etc/omachat-server
sudo /usr/local/bin/omachat-serverd --generate-secret /etc/omachat-server/server.key
sudo /usr/local/bin/omachat-serverd --generate-secret /etc/omachat-server/storage.key
sudo /usr/local/bin/omachat-serverd --generate-secret /etc/omachat-server/invites
sudo chown omachat-server:omachat-server /etc/omachat-server/server.key /etc/omachat-server/storage.key /etc/omachat-server/invites
sudo install -m 0644 ops/server/omachat-serverd.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now omachat-serverd
journalctl -u omachat-serverd -n 5
```

Run from the repository root after `cargo build --release -p omachat-server
--bins --locked`. This is a first-install procedure: do not regenerate existing
secrets when upgrading. The generator refuses to overwrite existing paths and
creates files with mode 0600. Root creates the files in the root-owned directory,
then transfers file ownership; the service can read the secrets but cannot
create or replace directory entries. The invite is one 64-character random hex
code; distribute it privately. Never paste key files into logs or tickets.

For rollback, stop the service and restore the previous compatible binary;
preserve `/var/lib/omachat-server`, `/etc/omachat-server`, and separate key backups.
Uninstalling the service must not delete messages or keys. For a consistent cold
backup, stop the server before copying the entire state directory; restore with
the matching storage key and owner-only permissions. A real restore rehearsal,
Caddy/TLS validation and documented key rotation remain deployment gates.

The journal shows the server public key. Publish it with the server URL so
clients pin it with `--server-public-key`.

Both secret files are 32 random bytes as hex and must stay owner-only; the
server refuses a file that is group- or world-readable. Losing
`storage.key` makes every stored message unreadable; back it up separately
from the database. Rotating it is not supported in this slice.

See `docs/hosted-server.md` for the protocol, threat model and what has been
verified.
