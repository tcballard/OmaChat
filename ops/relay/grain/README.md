# Grain relay bootstrap profile

This directory is a fail-closed operations profile for the first OmaChat
bootstrap relay. It is not evidence that a public relay has been deployed.

## Pinned implementation

- Grain release: `v0.7.1`
- Source commit: `c0709db6e59d57620ba2053c7078b1e07942d38c`
- Upstream source: <https://github.com/0ceanSlim/grain>
- License: MIT

The interoperability harness downloads an official release archive and checks
its platform-specific SHA-256 before execution. The Linux amd64 digest used by
CI is:

```text
e000dad4c35669a32284a66876b6171e23fee2a12bfbfcce7824ebc3316a602d
```

## Deliberate defaults

- NIP-42 authentication is required for every read and write.
- Kind `1059` historical reads, live delivery, and counts remain constrained
  by Grain to the authenticated `p`-tagged recipient.
- The internal listener is plain HTTP/WebSocket on port `8181`; a production
  reverse proxy must terminate TLS and expose only `wss://`.
- The configured relay URL is `wss://relay.omachat.invalid`. Deployment tooling
  must replace it with the exact public URL or authentication fails closed.
- Event size is capped at 64 KiB. Kind `10050` and `1059` have tighter rate and
  size policy entries.
- Connections and concurrent subscriptions remain bounded.
- Built-in index relays are empty. The bootstrap relay is not canonical truth
  and does not silently depend on third-party discovery services.
- Event purging is disabled. This prevents accidental message loss while issue
  #79 remains unresolved; it is not a final product retention promise.
- Backup forwarding is disabled. Availability comes from adding a separately
  operated relay later, not by treating one relay as protocol authority.

## Reproducible local probe

Run:

```sh
./scripts/test-grain-relay.sh
```

The probe uses independent BIP-340 event signing and a standard-library
WebSocket client. It verifies:

- unauthenticated publish and read rejection;
- valid NIP-42 authentication;
- invalid event/signature rejection;
- authenticated kind `1059` publication under a distinct wrapper key;
- recipient-only historical reads and counts;
- denial of the same data and count to an authenticated stranger;
- replaceable kind `0` profile behavior;
- exact NIP-65 kind `10002` read/write relay-list storage;
- exact NIP-17 kind `10050` inbox relay-list storage;
- signature and event-ID revalidation on every queried event;
- exact metadata and message event identity after a full relay restart.

The Rust suite separately verifies the NIP-44/NIP-59 cryptographic envelope and
OmaChat client delivery path. Passing this probe does not prove TLS, backups,
monitoring, public reachability, load capacity, or cross-Buzz messaging.

## Production blockers

Do not expose this profile publicly until all of these are resolved:

- choose the real relay domain and TLS operator;
- set and custody the relay owner key without placing a private key on disk;
- publish retention, privacy, posting, and terms URLs;
- decide issue #79 and configure tested backup/restore semantics;
- add monitoring for health, storage, connection, rejection, and latency data;
- enforce an aggregate per-authenticated-pubkey publish budget across
  connections, which Grain `v0.7.1` does not currently provide;
- define an agent loop budget and incident kill switch;
- run load, restore, upgrade, and rollback drills on the target Linux host;
- repeat the black-box probe through the real TLS endpoint.
