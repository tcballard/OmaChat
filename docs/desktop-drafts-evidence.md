# Desktop draft evidence

29 September 2026. Stacked implementation, not a release claim.

Local checks passed: pure JavaScript presentation/contact tests; draft recovery,
late acknowledgement, concurrent writer conflicts, disconnect/reconnect,
UTF-8 bounds, failed writes and revision-checked clearing tests; five offscreen
Qt interaction checks including saved-text conflict choice; launcher syntax.

The production view is loaded in Qt 6.8.3 with a fixture backend. This does not
prove Quickshell Process integration, an actual Wayland window, or live daemon
restart. The full bridge Unix-socket suite runs in GitHub CI because this editing
environment denies creation of Unix sockets. Rust storage/IPC tests run in CI.

Before release, run on Tom's Omarchy desktop: type and wait for saved status,
close/reopen both clients and daemon, edit one draft from two clients, interrupt
a save, exhaust storage, switch chats during send/save, restart during accepted
send, and inspect recovered-draft review. Confirm no plaintext cache exists.
Window-close interception is not implemented: explicitly verify the warning and
wait for saved status. Never claim offline or in-flight edits survive exit.
