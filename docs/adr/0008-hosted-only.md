# ADR 0008: Hosted messaging is the sole transport

Status: accepted by owner instruction, 2026-10-01.
Supersedes ADR 0007's retention decision and the Nostr transport/registry work in ADRs 0001–0005.

Remove Nostr rather than keeping it behind a feature flag or maintaining a fallback.
The hosted server owns account handles, workspace membership, history and receipts.
Remove the Nostr, mesh and standalone registry crates, relay services and operations,
contact links, geohash chat, relay setup, compatibility vectors and their CI jobs.
The desktop opens direct messages by server handle and configures one pinned server.

Keep the existing Ed25519 signing seed so hosted accounts remain accessible. Ignore
retired roots when decoding old identity records. Keep hosted drafts and cached messages;
exclude retired conversation identifiers. Do not silently delete unrelated sealed files.
Old daemon configuration fields fail closed. Desktop setup can replace them with the
hosted schema, retaining a private backup. This is a deliberate upgrade, not a Nostr runtime.

Hosted messages are not end-to-end encrypted. The operator can read them. Multi-device
accounts and recovery are still separate future work. Deployment and security review
remain required under the hosted delivery plan.
