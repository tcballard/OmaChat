# OC-006 BlueR dual-role qualification probe

Status: compile-checked probe pending named hardware captures

The disposable BlueR probe registers the pinned service and characteristic,
starts legacy connectable service-UUID advertising, keeps LE scanning active,
connects to a named companion adapter, and exchanges bytes in both directions.
Two machines run the same probe against each other. The JSON records controller
advertising capacity, local GATT, concurrent roles, traffic, and observed MTUs.

Build and run as the logged-in user; do not use `sudo`:

```sh
cargo build -p omachat-mesh --example bluer_dual_role_probe --release
target/release/examples/bluer_dual_role_probe \
  --adapter hci0 --peer AA:BB:CC:DD:EE:FF \
  --duration-seconds 1800 --output evidence/internal-hci0.json
```

Run it once for the target internal controller and once for a named USB
controller, with the companion configured reciprocally. A duration below 1800
seconds deliberately reports `incomplete` even when bytes flow.

BlueR 0.17.4 exposes acquired MTUs but not the negotiated ATT bearer count. Save
a concurrent `btmon` trace when permitted and record whether BlueZ establishes
EATT bearers. If trace access is denied, record the denial; do not add root,
ambient capabilities, a broad polkit rule, or an extended-advertising
requirement. Record adapter model, USB/PCI ID, kernel, firmware, BlueZ, and
BlueR versions.

The probe is not the production mesh manager.
