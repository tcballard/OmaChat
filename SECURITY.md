# Security and privacy

Report vulnerabilities using GitHub's private vulnerability-reporting flow for
this repository. Include version, platform and reproduction steps, with secrets
removed. No response-time or bounty promise exists before release.

The handle server uses TLS (except numeric-loopback development connections), a
pinned Ed25519 server key, and device-key challenge authentication. Obtain the
pin independently from the server operator. Never accept an unexpected replacement.
The server stores account handles and display names. It does not store chat.
The storage key seals a key-check record; losing it makes the database fail closed.

The daemon stores its device key in a sealed local store. A file key must be
private; Secret Service is supported. Compromise of the same user, the running
daemon, or the server defeats these boundaries. Accounts are currently bound to
one device; account recovery and multi-device support have not shipped.

IPC uses bounded JSON lines on a private Unix socket with SO_PEERCRED validation.
Only the daemon's effective UID is accepted, including rejection of root as a different UID.
Panic erasure requires a daemon-minted, single-use token with a 120-second lifetime,
passed through a private file. This protects against accidental or stale requests;
same-user processes can read that token and require OS-level isolation.

Panic erasure stops the server transport, fences in-flight operations, drops the
in-process keys and removes local key material. Cleanup failure is terminal.
Erasure cannot retract server account records, logs, snapshots or backups, and
is not a physical-overwrite guarantee on SSD or copy-on-write storage.

The hosted chat product and its threat model are archived on branch
`hosted-archive` at `825cf07123`. Current direction is
[ADR 0010](docs/adr/0010-nostr-identity.md). Nostr direct messages, a community
relay and BLE mesh are not implemented here. Deployment and an independent
security review remain outstanding.
