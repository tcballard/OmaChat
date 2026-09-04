# Legacy Waybar example

This is not the Omarchy Quattro path. For older Waybar setups, add a custom
module that executes `omachat-status.sh` every five seconds with JSON output.
It requires root-owned `/usr/bin/omachat-ctl`, `/usr/bin/jq`, and GNU
coreutils `/usr/bin/timeout`; none are resolved through ambient `PATH`.
Installation and configuration are manual;
the package never edits Waybar configuration.
