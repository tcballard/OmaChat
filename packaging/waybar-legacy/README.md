# Legacy Waybar example

This is not the Omarchy Quattro path. For older Waybar setups, add a custom
module that executes `omachat-status.sh` every five seconds with JSON output.
It requires `jq` and GNU `timeout`. Installation and configuration are manual;
the package never edits Waybar configuration.
