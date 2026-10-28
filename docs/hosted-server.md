# Handle server

`omachat-serverd` is the thin server left after [ADR 0010](adr/0010-nostr-identity.md)
archived the hosted chat product. It authenticates devices and stores handles.
It does not store messages, workspaces or channels. The websocket session is
kept so the process can later grow into the Omacon relay; that relay is not
built here.

The chat protocol, invite codes and desktop client are on branch
`hosted-archive` at commit `825cf07123`.

## What it does

One loopback WebSocket, one JSON object per text frame, at most 16 KiB.
A TLS reverse proxy owns the public socket. See `ops/server/`.

1. `hello {minimum_version, maximum_version, device_public_key}`. The device
   key is a hex Ed25519 public key. The reply is
   `{version, challenge, server_public_key, server_signature}`. Clients pin
   `server_public_key` out of band and verify the signature.
2. `authenticate {signature, display_name?}`. `signature` is the device's
   Ed25519 signature over
   `"omachat-server-auth-v1\0" || server_public_key || challenge || device_public_key`.
   An unknown device creates an account. A known device resumes its account
   and the stored display name is not overwritten.
3. After authentication: `status`, `claim-handle {handle}`, `resolve-handle {handle}`,
   `bind-nostr` and `unbind-nostr`.

`bind-nostr` carries the 32-byte x-only Nostr key, a 32-byte nonce, a unix
timestamp, an Ed25519 signature by the authenticated device, and a BIP-340
Schnorr signature by the Nostr key. Both signatures are over
`omachat-nostr-bind-v1\0`, the server public key, the account id, the claimed
handle, the Nostr key, the nonce and the timestamp. A proof is refused when
either signature is wrong, the timestamp is more than five minutes from the
server clock, the nonce was already used, or that Nostr key is already bound
to another handle. Binding again with a fresh proof replaces the account's
key. `unbind-nostr` is signed only by the device, so a lost `nsec` can still
be detached.

`GET /.well-known/nostr.json?name=<handle>` returns
`{"names":{"<handle>":"<64-hex pubkey>"}}` for a bound handle, with
`Access-Control-Allow-Origin: *`. Unknown names are HTTP 404 with
`{"names":{}}`. Names are matched case-insensitively and must be 1 to 64
characters from `a-z`, `0-9`, `-`, `_` and `.` after lowercasing. A missing
or illegal name is HTTP 400. `--nip05-relay wss://...` (repeatable) adds the
optional NIP-05 `relays` object; otherwise that field is omitted. Caddy
proxies this path to the same loopback port as the WebSocket.

Handles follow `omachat-crypto`: 3 to 32 characters, lowercase letters, digits
and `_`, starting with a letter. An account claims one handle. A handle cannot
belong to two accounts.

The database file is `server.db`. Schema version 2 is accounts, devices and
handles. Schema version 1, the archived chat database, is refused. The storage
key seals a key-check record so the wrong key cannot open the file. Account
rows themselves are not encrypted.

There is no invite file and no closed-registration mode. The listener still
refuses a non-loopback address.

## Daemon

`omachatd` speaks this protocol when `hosted` is set in its configuration.
The daemon signs with its existing Ed25519 device key. IPC v4 exposes
`hosted-claim-handle` and `hosted-resolve-handle`. Chat IPC methods are rejected.
