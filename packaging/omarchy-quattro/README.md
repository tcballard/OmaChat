# Optional Omarchy Quattro widget

This plugin performs one non-overlapping `omachat-ctl status --json` poll every
five seconds, wrapped in a one-second timeout. Daemon absence and malformed
output render `OC —`; they do not block the shell. The plugin has no install
hook, privileges, configuration writer, or automatic enablement.

On an Omarchy v4.0.1/Quattro machine, validate before enabling:

```sh
omarchy plugin validate ./packaging/omarchy-quattro
cp -R packaging/omarchy-quattro ~/.config/omarchy/plugins/tcballard.omachat-status
omarchy-shell shell rescanPlugins
omarchy plugin enable tcballard.omachat-status
```

The copy step is intentional: Quattro validation rejects symlinked plugin
trees. Remove with `omarchy plugin remove tcballard.omachat-status`; no user
configuration is edited by this repository.
