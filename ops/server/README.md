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
sudo install -d -m 0750 -o root -g omachat-server /etc/omachat-server
sudo -u omachat-server omachat-serverd --generate-secret /etc/omachat-server/server.key
sudo -u omachat-server omachat-serverd --generate-secret /etc/omachat-server/storage.key
sudo -u omachat-server sh -c 'umask 077; head -c 24 /dev/urandom | base64 > /etc/omachat-server/invites'
sudo install -m 0644 omachat-serverd.service /etc/systemd/system/
sudo systemctl enable --now omachat-serverd
journalctl -u omachat-serverd -n 5
```

The journal shows the server public key. Publish it with the server URL so
clients pin it with `--server-public-key`.

Both secret files are 32 random bytes as hex and must stay owner-only; the
server refuses a file that is group- or world-readable. Losing
`storage.key` makes every stored message unreadable; back it up separately
from the database. Rotating it is not supported in this slice.

See `docs/hosted-server.md` for the protocol, threat model and what has been
verified.
