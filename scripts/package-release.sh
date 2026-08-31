#!/bin/sh
set -eu

version=${1:?usage: package-release.sh VERSION COMMIT OUTPUT_DIRECTORY}
commit=${2:?usage: package-release.sh VERSION COMMIT OUTPUT_DIRECTORY}
output=${3:?usage: package-release.sh VERSION COMMIT OUTPUT_DIRECTORY}
case "$version" in *[!0-9.]*|'') echo "invalid version" >&2; exit 2;; esac
test -d "$output" || mkdir -p "$output"
archive="$output/omachat-$version.tar.gz"
git archive --format=tar --prefix="OmaChat-$version/" "$commit" | gzip -n -9 >"$archive"
sha256sum "$archive" >"$archive.sha256"
printf '%s\n' "created $archive and $archive.sha256"
