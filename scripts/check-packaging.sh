#!/bin/sh
set -eu

test -f packaging/systemd/omachatd.service
for page in omachat-ctl.1 omachatd.8 omachat-protocol.7; do
  test -s "packaging/man/$page"
done
test -s packaging/omarchy-quattro/manifest.json
test -s packaging/omarchy-quattro/Widget.qml
test -x scripts/package-release.sh
sh -n scripts/package-release.sh
test -x scripts/check-release-size.sh
sh -n scripts/check-release-size.sh
test -x scripts/test-check-release-size.sh
sh -n scripts/test-check-release-size.sh
for shell in omachat-ctl.bash _omachat-ctl omachat-ctl.fish; do
  test -s "packaging/completions/$shell"
done
for completion in omachat-ctl.bash _omachat-ctl; do
  grep -Fq -- '--qr' "packaging/completions/$completion"
done
grep -Fq -- '-l qr' packaging/completions/omachat-ctl.fish
grep -Fqx "pkgdesc='Local identity daemon and handle server for Omarchy'" packaging/arch/omachat/PKGBUILD
grep -Fqx "pkgdesc='Local identity daemon and handle server for Omarchy (git)'" packaging/arch/omachat-git/PKGBUILD
grep -Fqx 'Description=OmaChat identity daemon and handle client' packaging/systemd/omachatd.service
if command -v mandoc >/dev/null 2>&1; then
  for page in packaging/man/*; do mandoc -T lint "$page"; done
fi
