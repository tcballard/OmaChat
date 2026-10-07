# Security and privacy

Report vulnerabilities using GitHub's private vulnerability-reporting flow for
this repository. Include version, platform and reproduction steps, with secrets
and message content removed. No response-time or bounty promise exists before release.

Hosted messaging uses TLS (except numeric-loopback development connections), a
pinned Ed25519 server key, and device-key challenge authentication. Obtain the
pin independently from the server operator. Never accept an unexpected replacement.
The server operator can read every message; storage encryption is not end-to-end encryption.
The server also sees account handles, membership, message timing and receipt metadata.

The daemon stores its device key, drafts and recent history in a sealed local
store. A file key must be private; Secret Service is supported. Compromise of the
same user, the running daemon, the server or its storage keys defeats these boundaries.
Hosted accounts are currently bound to one device; account recovery and multi-device
support have not shipped. Protect the local credential and backups accordingly.

IPC uses bounded JSON lines on a private Unix socket with SO_PEERCRED validation.
Only the daemon's effective UID is accepted, including rejection of root as a different UID.
Panic erasure requires a daemon-minted, single-use token with a 120-second lifetime,
passed through a private file. This protects against accidental or stale requests;
same-user processes can read that token and require OS-level isolation.

Panic erasure stops the hosted transport, fences in-flight operations, drops the
in-process keys and removes local key material before ciphertext. Cleanup failure
is terminal. Erasure cannot retract server messages, peer copies, logs, snapshots
or backups, and is not a physical-overwrite guarantee on SSD or copy-on-write storage.

Nostr and its compatibility/security claims are retired. See
[the hosted review](docs/hosted-server.md) for verified claims and known limitations.
Deployment and an independent security review remain outstanding.
