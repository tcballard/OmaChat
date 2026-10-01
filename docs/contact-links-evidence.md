> Historical document. Nostr and its compatibility/relay workflows are retired by [ADR 0008](adr/0008-hosted-only.md). See [the hosted plan](hosted-server-plan.md) for current work.

# Contact-link slice — 29 September 2026

Stacked on #231 at `7f831b812c2d110826ae490e9ecfc3ed260d1c2b`.
Input hashes are in `desktop/SHA256SUMS`. Prior desktop evidence remains scoped
to its recorded commits; it is not a claim that these new changes ran earlier.

Implemented NIP-19 npub/nprofile display decoding and npub encoding, plus NIP-21
nostr: contact links. Inspected the primary Nostr NIPs 19 and 21 on this date.
Tests use their published public-key/profile vectors. No protocol transport or
cryptography changed; this is display/input encoding. No new runtime dependency.

Reproduced locally on Python 3.12 / Qt 6.8.3 offscreen / Node.js:

- `node desktop/tests/test_contact.js`: passed; published vectors, checksum,
  padding, mixed-case, size, invalid/duplicate TLV keys, unknown TLV handling,
  private-key rejection and ignored relay hints.
- `python3 -m unittest discover -s desktop/tests -p 'test_view.py' -v`: four
  passing UI tests, including opening a nostr:npub contact and refusing nsec.

Not run locally: production Quickshell/Wayland, live relay exchange, OS-level
nostr: handler registration (not implemented). Copy/paste is the supported
contact-link path. No production service or automatic relay selection is added.
The desktop CI workflow also runs the contact vector suite on this PR.
