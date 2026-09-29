# Sealed draft IPC (version 1)

Stacked after desktop contact links. This layer adds the daemon contract; the
composer integration is a separate follow-up. No desktop persistence is claimed
until that integration lands.

IPC v2 status advertises `drafts_version: 1`. Older clients can ignore this field.
Clients must check it before issuing these additive methods:

- `list-drafts`: returns `drafts`, a bounded list of conversation/revision pairs.
- `get-draft` with `conversation`: returns conversation, text, revision.
- `save-draft` with conversation, text, expected_revision: returns the current
  conversation/text/revision and `saved`. False means a conflict; preserve the
  user's local text and ask which version to keep. Never blindly retry a save.

Revisions are integers representable exactly by JavaScript. Empty text deletes a
draft. Missing entries use the store generation as their revision, preventing a
stale create after a create/delete cycle. Changes in other missing conversations
can therefore cause conservative conflicts. No-op saves still check revision.

One daemon owns the sealed store. Read/compare/write runs under its existing
storage transaction and panic operation gate. The store uses the existing atomic,
authenticated encryption writer. A response acknowledges persistence only after
that writer succeeds. A disconnected client must reread to resolve an unknown
save result. No draft text enters events or the general subscription snapshot.

The schema is versioned and strict. Unreadable, corrupt, or newer records fail
closed without replacement. Limits: 64 nonempty drafts, 4096 UTF-8 bytes per text,
256 bytes per conversation ID, 512 KiB encoded record. Conversation IDs are opaque
`dm:`, `room:`, or `#` names; saving does not validate membership or send anything.
Reaching a limit refuses the change and preserves existing data. Panic erase uses
the existing whole-store erase path; drafts have no separate persistent cache.

Tests cover ciphertext inspection, store reopen, stale writers, deletion/recreate,
unknown schema, corruption, capacity, UTF-8 limits, strict request decoding, and
IPC restart. Rust execution is delegated to repository CI because the editing
workspace has no Rust toolchain. Actual desktop restart remains a later gate.
