# XPS live testing plan for the desktop stack

Target: Tom's Dell XPS running Omarchy, branch `feat/desktop-live-hardening`
(the top of PRs #230–#238). Nothing below merges, tags, releases or deploys.
The plan has two phases: a scratch daemon that cannot touch real data for the
failure paths, then the real daemon and authorised relays for messaging.

Record each step as passed, failed or not run. Fixture and container results
never substitute for these.

## 0. Fresh checkout, build and local proof

```sh
git clone https://github.com/tcballard/OmaChat.git ~/src/OmaChat-desktop
cd ~/src/OmaChat-desktop
git checkout feat/desktop-live-hardening
git log -1 --format='%H %s'
command -v quickshell python3 cargo
quickshell --version
cargo build --workspace --bins --release --locked
sha256sum -c desktop/SHA256SUMS
node desktop/tests/test_state.js
node desktop/tests/test_contact.js
node desktop/tests/test_drafts.js
python3 -m unittest discover -s desktop/tests -p 'test_bridge.py' -v
python3 -m unittest discover -s desktop/tests -p 'test_setup.py' -v
python3 scripts/test-desktop-bridge.py
sh -n desktop/omachat-desktop
```

`test-desktop-bridge.py` runs the release daemon from a temporary directory
with a file key; it proves the adapter contract on this machine without
opening your account. The Qt suite is optional here; it needs a PySide6 venv
as described in `desktop/README.md` and adds nothing a live window does not.

## 1. Preserve identity, configuration and messages first

```sh
stamp=$(date +%Y%m%d-%H%M%S)
mkdir -m 700 -p ~/omachat-backups
tar -C ~ -cf ~/omachat-backups/omachat-$stamp.tar \
  .local/state/omachat .local/state/omachat-anchors .config/omachat 2>/dev/null
chmod 600 ~/omachat-backups/omachat-$stamp.tar
tar -tf ~/omachat-backups/omachat-$stamp.tar | head
```

Sealed records are useless without the master key. With the default keyring
provider the key stays in Secret Service, so the archive protects against
accidental deletion of records and configuration, not against a lost keyring.
Do not copy the keyring entry anywhere. Confirm which daemon serves you:

```sh
systemctl --user status omachatd.service --no-pager
pgrep -a omachatd
./target/release/omachat-ctl status
```

The status JSON must show `"drafts_version":1`; an older daemon has no
drafts, and the desktop then keeps session-only drafts. If a packaged or
older daemon is running, stop it and run this build with the same arguments
you normally use (packaged users: `systemctl --user stop omachatd.service`,
then `./target/release/omachatd`). The state, socket and configuration paths
are unchanged, so existing identity, history and outbox are reused.

## 2. Scratch daemon: failure paths without risk

Everything here uses a separate socket, state, key and configuration.

```sh
mkdir -m 700 -p /tmp/omachat-scratch
cat > /tmp/omachat-scratch/config.json <<'JSON'
{ "storage_provider": "file", "dm_relays": [] }
JSON
./target/release/omachatd --config /tmp/omachat-scratch/config.json \
  --state /tmp/omachat-scratch/state --socket /tmp/omachat-scratch/omachat.sock
```

In a second terminal:

```sh
cd ~/src/OmaChat-desktop
OMACHAT_SOCKET=/tmp/omachat-scratch/omachat.sock \
OMACHAT_CONFIG=/tmp/omachat-scratch/config.json \
sh desktop/omachat-desktop 2>&1 | tee /tmp/omachat-scratch/desktop-1.log
```

A third terminal with the same command gives the second window
(`desktop-2.log`). Quickshell runs duplicate instances of the same shell path
unless started with `--no-duplicate`.

Check, in order:

1. **Launch and process integration.** The window opens; the log has no QML
   warnings or `qml: ` errors; `pgrep -af bridge.py` shows one adapter per
   window; the green marker and "Connected to local daemon" appear.
2. **Focus, narrow layouts and themes.** Tab and Shift+Tab move visible focus
   through the sidebar, composer and buttons. Resize the window below 760 px:
   the sidebar and chat swap with the "Chats" button; the minimum size holds
   at 440×480. Run `omarchy-theme-set` (or the Omarchy theme menu) for a light
   and a dark theme and relaunch each time; text stays readable and the
   fallback palette is not used while `~/.config/omarchy/current/theme/colors.toml`
   exists.
3. **Drafts across restart.** Ctrl+N, paste any `npub…` or 64-hex key, type,
   wait for "Draft saved securely on this device." Close the window
   normally: with the draft saved, no dialog may appear. Relaunch:
   the draft returns as "Recovered draft" and Send stays disabled until
   "I checked". Stop the scratch daemon with Ctrl+C while typing: status shows
   "Offline". Restart it: status returns to saved without a conflict.
4. **Two clients, one draft.** Open the same conversation in both windows.
   Type in window 1 and wait for saved. Type in window 2: it must show
   "Another client changed this draft" with window 1's text; choose each
   option once and confirm the composer content. Identical text typed in both
   must not raise a conflict.
5. **Switching during saves and sends.** Type in chat A, switch to chat B
   within 600 ms, type there, switch back: neither text is lost or swapped;
   the sidebar previews show both drafts. Send in A (the scratch daemon
   accepts the legacy DM profile only if a relay is set; with none, the
   desktop refuses with the NIP-17 message, which is the expected result).
6. **Timeout and unknown outcome.** The daemon refuses to start with an
   unreachable NIP-17 relay, so use a room instead: add
   `"joined_geohashes": ["gcpvj"]` to the scratch config, restart the daemon,
   select `#gcpvj`, type, then pause the daemon with
   `kill -STOP $(pgrep -f omachat-scratch/state)` and click Send. The button
   shows "Sending…" and the window stays connected; at 30 s it shows
   "Delivery is unknown" with "I checked — allow another send". Resume with
   `kill -CONT` on the same PID: the message appears once as "Created
   locally" and the draft stays. Nothing may be resent by the desktop.
   Separately, configure `"dm_relays": ["wss://192.0.2.1"]` and restart: the
   daemon must exit with "relay authentication timed out" and the desktop
   must show the missing-socket notice until the URL is corrected.
7. **Storage failure.** With the daemon running as your user, make its
   records read-only: `chmod 500 /tmp/omachat-scratch/state/records`, type
   in a draft: the status must show the daemon's storage error and "Retry
   draft recovery"; text stays. Restore with `chmod 700` on the same
   directory and click retry: the draft saves.
8. **Close protection.** With unsaved text, use the Omarchy close-window
   binding (Super+W by default) and the title-bar close if present. The
   dialog must appear both times. Test Keep editing, Save and close (window
   closes only after "saved"), and Close anyway. With the daemon stopped and
   text typed, Save and close must be disabled and Close anyway must warn.
   Then `kill -TERM $(pgrep -f 'quickshell -p')` from another terminal: the
   window closes without a dialog and the adapter exits (`pgrep -f bridge.py`
   is empty). This is the documented forced-termination loss path.
9. **Hot reload is off.** With text typed, `touch desktop/ChatView.qml`
   (or `git status` after editing a comment): the window must not reload.
10. **Relay configuration, custom path.** Open "Set up messaging"; the path
    field shows `/tmp/omachat-scratch/config.json`. Add `wss://relay.example`
    and save; confirm the backup file next to the config, mode 600, the
    preserved `storage_provider` field, and the restart notice. Change the
    file in an editor, then save again without reloading: the dialog must
    refuse until reloaded. Enter a bad URL (`https://…`): refused. Close with
    unapplied edits: the window's close guard must mention relay settings.
11. **Relay configuration, default path.** Only after the backup in section 1.
    Launch without `OMACHAT_CONFIG` and point the dialog at nothing: the path
    shows `~/.config/omachat/config.json`. Load, change nothing, save once,
    and diff the backup against the file: only `dm_relays`/`rooms.relays`
    formatting may differ. Restore the backup if anything else changed.

Stop the scratch daemon and remove `/tmp/omachat-scratch` when done.

## 3. Real daemon and authorised relays

Requires two machines (or one machine and a second authorised device) and
your authorised NIP-17 inbox relay and NIP-29 room relay.

```sh
./target/release/omachatd            # or your usual arguments
./target/release/omachat-ctl status  # dm_relay_count > 0 after configuration
sh desktop/omachat-desktop 2>&1 | tee ~/omachat-desktop.log
```

1. Configure the NIP-17 relay through "Set up messaging" if not already set,
   restart the daemon, and confirm `dm_relay_count` in `omachat-ctl status`.
2. On each client open "My identity & connection", copy the contact link,
   and paste it into the other client's "New message". The preview must show
   the format and hex key; a `nostr:` link with relay hints must say hints
   are ignored.
3. Exchange messages in both directions. Each outgoing message must move to
   "Stored by relay"; the other side must show it without duplicates. Relay
   storage is not delivery proof, so also confirm receipt out of band.
4. Send while the receiver is offline, then bring it back: the message must
   arrive once. Disconnect the sender's network mid-send: expect unknown
   outcome, no automatic resend, and at most one copy on the receiver after
   reconnection.
5. Restart the daemon on one side during a conversation: the desktop must
   reconnect with a fresh snapshot, keep drafts, and mark any in-flight send
   unknown rather than resending it.
6. Rooms: configure the NIP-29 relay, restart, "Join" with a room ID you are
   authorised for. The join notice must say admission is the relay's decision.
   Exchange room messages; the header must state that rooms are not
   end-to-end encrypted DMs.
7. Close both clients through the guard with a saved draft on each and
   reopen: drafts recover per device only; they must not appear on the other
   machine.

## 4. Report

For every numbered item, record passed, failed (with the log line and what
you saw) or not run. Attach `desktop-*.log` extracts for QML warnings. The
stack stays draft until this report exists.
