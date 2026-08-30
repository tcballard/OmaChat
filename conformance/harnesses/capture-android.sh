#!/usr/bin/env bash
set -euo pipefail

if [[ $# -ne 3 ]]; then
  echo "usage: $0 <pinned-bitchat-android-checkout> <swift-capture-directory> <capture-directory>" >&2
  exit 2
fi

upstream_checkout=$1
swift_capture_directory=$2
capture_directory=$3
script_directory=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
expected_revision=93e9594bad3e537b4ec6fd096c0fde7533f22e74

actual_revision=$(git -C "$upstream_checkout" rev-parse HEAD)
if [[ "$actual_revision" != "$expected_revision" ]]; then
  echo "Android checkout is $actual_revision; expected $expected_revision" >&2
  exit 1
fi

rm -rf -- "$capture_directory"
mkdir -p -- "$capture_directory"
install -m 0644 \
  "$script_directory/android/OmaChatNostrShapeCaptureTest.kt" \
  "$upstream_checkout/app/src/test/kotlin/com/bitchat/android/nostr/OmaChatNostrShapeCaptureTest.kt"

OMACHAT_SWIFT_CAPTURE_DIR="$swift_capture_directory" \
OMACHAT_CAPTURE_DIR="$capture_directory" \
"$upstream_checkout/gradlew" \
  --project-dir "$upstream_checkout" \
  --no-daemon \
  --no-build-cache \
  --rerun-tasks \
  :app:testDebugUnitTest \
  --tests com.bitchat.android.nostr.OmaChatNostrShapeCaptureTest
