#!/bin/sh
set -eu

test -f packaging/systemd/omachatd.service
test -f packaging/desktop/omachat.desktop
for page in omachat.1 omachat-ctl.1 omachatd.8 omachat-protocol.7; do
  test -s "packaging/man/$page"
done
test -s packaging/omarchy-quattro/manifest.json
test -s packaging/omarchy-quattro/Widget.qml
test -x scripts/package-release.sh
sh -n scripts/package-release.sh
for shell in omachat.bash omachat-ctl.bash _omachat _omachat-ctl omachat.fish omachat-ctl.fish; do
  test -s "packaging/completions/$shell"
done
for completion in omachat-ctl.bash _omachat-ctl; do
  grep -Fq -- '--qr' "packaging/completions/$completion"
done
grep -Fq -- '-l qr' packaging/completions/omachat-ctl.fish
grep -Fq 'Only the Nostr transport is currently wired into the daemon' packaging/man/omachatd.8
! grep -Fq 'relay and mesh transports' packaging/man/omachatd.8
grep -Fqx 'Description=OmaChat Nostr and IPC daemon' packaging/systemd/omachatd.service
if command -v mandoc >/dev/null 2>&1; then
  for page in packaging/man/*; do mandoc -T lint "$page"; done
fi
