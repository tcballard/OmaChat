# OC-008 proxy and Tor transport probe

Status: portable transport proof complete; live system-Tor and Arti captures pending

The test-only transport probe opens a WebSocket directly or through SOCKS5,
performs an echo round trip, closes it, and reconnects. The SOCKS path passes an
unresolved `(hostname, port)` to `tokio-socks`; the proxy owns DNS. TLS and the
WebSocket request retain the original `wss://` hostname for certificate
verification, SNI, and `Host`.

```sh
cargo run -p omachat-nostr --example transport_probe -- \
  --url wss://relay.example/path --attempts 2
cargo run -p omachat-nostr --example transport_probe -- \
  --url wss://relay.example/path --socks5 127.0.0.1:9050 --attempts 2
```

`transport_semantics.rs` supplies a hermetic TLS relay and recording SOCKS5
proxy. Its `.invalid` hostname cannot resolve through public DNS. The test
requires two `ATYP=DOMAIN` requests, original-host TLS/SNI and `Host`, echo,
clean close, and reconnect. The live G0 capture must additionally record system
DNS observations on Omarchy v4.0.1.

Arti is a separately locked, standalone disposable package. It is outside the
OmaChat workspace and its dependency graph never enters the product lockfile:

```sh
cargo run --manifest-path conformance/probes/arti/Cargo.toml -- \
  --host relay.example --port 443 --timeout-seconds 180
```

Its bootstrap cache is persistent state. Cancellation must drop the client and
outstanding streams, and daemon shutdown must await owned tasks. The probe drops
the stream and client before reporting success. No user-facing Tor claim is
enabled by this spike.

Arti 0.45.0 currently includes `rsa` 0.9.10 through key-management code, which
RustSec flags for a private-key timing side channel (RUSTSEC-2023-0071). This
probe neither creates nor operates on RSA private keys, but that dependency is
still disqualifying for production adoption. It is recorded here rather than
ignored in OmaChat's root audit. OC-008 can prove bootstrap feasibility; a
production embedded-Tor decision requires a dependency graph with no active
security advisory.
