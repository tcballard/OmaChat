# Security and privacy

## Reporting a vulnerability

Do not open a public issue for an exploitable vulnerability or leaked secret.
Use GitHub's private vulnerability-reporting flow for this repository. Include
the exact OmaChat version/profile line, platform, reproduction steps, and the
minimum necessary logs. Never include private keys, decrypted private content,
or an unredacted state directory.

No response-time or bounty promise exists before the first release.

## Security boundary

OmaChat protects local records with XChaCha20-Poly1305 under one randomly
generated master key. Record names are authenticated. Writes use a private
temporary file, fsync, atomic rename, and directory sync. Secret Service is the
preferred provider; on Omarchy this is software storage through GNOME Keyring,
not a secure enclave or hardware-backed-key claim. File mode stores a 0600 key
inside the 0700 state directory. Provider selection is sticky and a missing
selected key fails closed instead of generating a replacement.

Long-term Noise, Ed25519 signing, stable private-Nostr, and Nostr derivation
roots are independent. Geohash identities and bridge identities are separated
by derivation domains. Authenticated Noise state, not public announcements,
pins peer keys. A changed pinned key fails closed until the user resolves it.

IPC is versioned, length bounded, and carried over a 0600 Unix socket. The
systemd user service restricts writable paths and privileges, but Bluetooth,
network, Unix-socket, and user-session D-Bus access remain necessary.

## Metadata and network limits

Encryption does not hide all metadata. Relays, peers, local administrators,
network observers, and Bluetooth observers may learn timing, volume, relay
selection, approximate geohash participation, radio presence, routing tags,
message sizes, and availability. Rotating courier tags are routing identifiers,
not secrets from a peer that retained the recipient's public key. Nostr events
remain visible to relays according to their outer format and retention policy.

OmaChat cannot retract messages, courier envelopes, event metadata, or keys
already copied to peers, relays, logs, backups, or monitoring systems. Blocking
hides authenticated content locally; it cannot make a sender stop transmitting.
Public chat is public. The six-hour sealed archive stores only validated public
events; private plaintext must never enter it.

## Private-message and compatibility limits

The private Nostr envelope is bitchat-specific (kinds 14, 13, and 1059), not a
generic NIP-44 or standard-Nostr-DM promise. Swift v1.7.1 is normative. Android
v2.0.1 is an acceptance peer only for features it ships. In particular, that
Android release does not implement courier v1/v2, signed one-time prekeys, RSR,
or the current carrier/rendezvous bridge.

Courier v1 uses Noise X but lacks forward secrecy. Courier v2 uses signed
one-time prekeys and retains a consumed grace key for delayed redelivery for up
to 48 hours. Relay courier drops use throwaway outer signers, but relays still
observe timing, routing tags, expiration, and ciphertext size. Full bridge
claims remain feature-gated until pinned Swift live tests prove carrier type 28,
`r`/optional `m` rendezvous events, loop prevention, and identity separation.

## Panic erase

`omachat-ctl panic --confirm ERASE` rejects new work, removes the selected
master key before unlinking ciphertext, syncs directory metadata, zeroizes the
in-process master key and identity, and stops the daemon. Captured ciphertext
cannot be opened with the newly generated key after restart.

This is cryptographic erasure, not guaranteed physical overwrite. Copy-on-write
filesystems, SSD wear levelling, swap, hibernation, crash dumps, snapshots,
backups, forensic memory capture, and network/peer copies can retain data. Panic
does not delete anything from a relay or another device. File-key deletion is
only as strong as the filesystem and backup policy; Secret Service deletion is
only as strong as its implementation and unlocked collection.

## Availability

OmaChat is not a 24/7 service guarantee. It operates only while the machine is
powered and awake and the user service, key provider, network, relay, BlueZ,
and adapter are usable. Suspend, logout without owner-enabled linger, radio
reset, captive networks, proxy failure, relay policy, or keyring lock may stop
delivery. Store-and-forward improves delay tolerance; it does not guarantee
delivery, ordering, secrecy after endpoint compromise, or permanent retention.
