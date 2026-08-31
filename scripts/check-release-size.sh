#!/bin/sh
set -eu

# The complete installed executable set must remain at or below 10 MiB.
maximum_total_bytes=$((10 * 1024 * 1024))
target_directory=${CARGO_TARGET_DIR:-target}
release_directory=$target_directory/release
total_bytes=0

for binary in omachatd omachat omachat-ctl; do
  path=$release_directory/$binary
  if [ ! -f "$path" ] || [ ! -x "$path" ]; then
    echo "release-size: missing executable $path" >&2
    exit 1
  fi

  bytes=$(wc -c < "$path" | tr -d '[:space:]')
  case $bytes in
    ''|*[!0-9]*)
      echo "release-size: could not measure $path" >&2
      exit 1
      ;;
  esac
  kibibytes=$(((bytes + 1023) / 1024))
  printf 'release-size: %s = %s bytes (%s KiB)\n' "$binary" "$bytes" "$kibibytes"
  total_bytes=$((total_bytes + bytes))
done

total_kibibytes=$(((total_bytes + 1023) / 1024))
printf 'release-size: aggregate = %s bytes (%s KiB); ceiling = %s bytes (10 MiB)\n' \
  "$total_bytes" "$total_kibibytes" "$maximum_total_bytes"

if [ "$total_bytes" -gt "$maximum_total_bytes" ]; then
  echo "release-size: aggregate executable size exceeds the 10 MiB ceiling" >&2
  exit 1
fi
