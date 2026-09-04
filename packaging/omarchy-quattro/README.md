# Optional Omarchy Quattro widget

This plugin performs one non-overlapping `omachat-ctl status --json` poll every
five seconds, wrapped in a one-second timeout. Daemon absence and malformed
output render `OC —`; they do not block the shell. The plugin has no install
hook, privileges, configuration writer, or automatic enablement.

The runtime contract is Omarchy v4.0.1's Quattro plugin API and the Quickshell
version supplied by that Omarchy release; standalone or floating Quickshell
builds are not claimed compatible. The widget requires root-owned
`/usr/bin/omachat-ctl` and GNU coreutils `/usr/bin/timeout`. It never resolves
executables through ambient `PATH`. `omachat-ctl` emits one IPC response whose
protocol line is capped at 64 KiB, bounding the complete-output collector; the
one-second wrapper remains a separate wall-clock bound.

On an Omarchy v4.0.1/Quattro machine with the packaged OmaChat CLI installed,
validate before enabling:

```sh
omarchy plugin validate ./packaging/omarchy-quattro
cp -R packaging/omarchy-quattro ~/.config/omarchy/plugins/tcballard.omachat-status
omarchy-shell shell rescanPlugins
omarchy plugin enable tcballard.omachat-status
```

The copy step is intentional: Quattro validation rejects symlinked plugin
trees. Remove with `omarchy plugin remove tcballard.omachat-status`; no user
configuration is edited by this repository.
