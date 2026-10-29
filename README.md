# OmaChat

<a href="https://github.com/tcballard/omarchy-badges"><img src="https://raw.githubusercontent.com/tcballard/omarchy-badges/75975e5b5bf75e7ede3764bcd2950046f7abfe2c/badges/v1/omarchy-app.svg" alt="Omarchy App" height="20"></a>

OmaChat is a Nostr client again. [ADR 0010](docs/adr/0010-nostr-identity.md)
seals an explicit `nostr-identity-v1` key and binds it to an `@handle`.
[ADR 0011](docs/adr/0011-nostr-messaging.md) restores gift-wrapped direct
messages, the `omachat` terminal, and the Quickshell desktop on that key.

The old Slack/Discord-style product remains on branch `hosted-archive` at
commit `825cf07123`. It is not developed on `main`.

**Development preview; no release is deployed.** `main` keeps a local daemon,
a terminal client, a control CLI, a Quickshell window, and a loopback handle
server. The server authenticates an Ed25519 device key and stores one
`@handle` per account. It does not store chat. A schema-version-1 chat
database is refused.

Build with Rust 1.98.0: `cargo build --workspace --bins`. Configure one server
URL and its independently obtained public key in `omachatd`'s `hosted` settings
when the daemon should claim or resolve handles.
See [server operations](ops/server/README.md).

The workspace contains protocol, crypto, Nostr transport, sealed store, handle
server, daemon, terminal, and CLI crates. The installed client binaries
(`omachatd`, `omachat`, `omachat-ctl`) retain a 10 MiB aggregate release size
ceiling. IPC v4 rejects older clients; update the clients and daemon together.
Existing device signing credentials remain valid. A Nostr key is not derived
from the device key.

```sh
omachat-ctl identity generate
omachat-ctl identity show
omachat-ctl identity export
omachat-ctl identity import nsec1...
omachat-ctl hosted-claim-handle alice
omachat-ctl identity bind
curl -sI http://127.0.0.1:7448/.well-known/nostr.json?name=alice
```

`identity export` is the only command that prints an `nsec`. `identity show`
prints the `npub`. Bind fails until the account has claimed a handle and the
daemon is connected to the server. The curl above is against the loopback
listener; through Caddy the same path is `https://<host>/.well-known/nostr.json?name=alice`
and the response includes `Access-Control-Allow-Origin: *`.

Direct messages use the relays in `dm_relays` (or the sealed list saved from
the UI). Put the same `wss://` relay on both daemons, then:

```sh
omachatd
omachat
# or: sh desktop/omachat-desktop
```

Opening `omachat` or the desktop calls `chat-prepare` and seals a Nostr key
when you do not already have one. In the terminal: `/npub` shows the public
key, `/contact add npub1...` or `/contact add name@domain` adds someone,
`/relays set wss://relay.example` saves relays, and typing a line sends a
gift wrap. `/handle claim alice` then `/handle bind` publishes the NIP-05
binding. The desktop has the same actions, including a Copy button for the
`npub`. See [desktop/README.md](desktop/README.md).

`omachat-ctl send <npub-or-name@domain> hello` sends without opening a UI.
`contacts-add`, `relays-set`, and `chat-prepare` are the matching commands.

Run `cargo fmt --all -- --check`, `cargo clippy --workspace --all-targets --locked -- -D warnings`,
and `cargo test --workspace --locked` after building.
Deployment, security review, account recovery and multi-device support remain outstanding.
A community Omacon relay is optional future infrastructure. BLE mesh remains
the lowest-priority future work; neither is in this tree. See [ADR 0011](docs/adr/0011-nostr-messaging.md).

The [Nostr acceptance gate](docs/nostr-e2e.md) exercises the full local flow and
independent cryptographic interoperability. Public handles use the
[domain deployment procedure](ops/server/README.md#publish-nip-05-on-your-domain).

All implementation changes use pull requests. Pull requests are not merged without explicit owner approval.

See [security and privacy](SECURITY.md). Licensed under [Zero-Clause BSD](LICENSE).
The project name remains provisional pending a separate adoption-grade clearance review.

For the archived chat product, check out `hosted-archive` rather than pointing
this binary at a chat database. Server data and secrets must survive uninstall;
see [server operations](ops/server/README.md).
