#!/usr/bin/env bash
set -euo pipefail

if [[ $# -ne 2 ]]; then
  echo "usage: $0 <pinned-bitchat-swift-checkout> <capture-directory>" >&2
  exit 2
fi

upstream_checkout=$1
capture_directory=$2
script_directory=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
expected_revision=9edb7c26ef7bdcf3bb29e7907b38997f8d5cd0fa

actual_revision=$(git -C "$upstream_checkout" rev-parse HEAD)
if [[ "$actual_revision" != "$expected_revision" ]]; then
  echo "Swift checkout is $actual_revision; expected $expected_revision" >&2
  exit 1
fi

rm -rf -- "$capture_directory"
mkdir -p -- "$capture_directory"
install -m 0644 \
  "$script_directory/swift/OmaChatCryptoCaptureTests.swift" \
  "$upstream_checkout/bitchatTests/OmaChatCryptoCaptureTests.swift"

OMACHAT_CAPTURE_DIR="$capture_directory" \
BITCHAT_SKIP_PERF_BASELINES=1 \
swift test \
  --package-path "$upstream_checkout" \
  --filter OmaChatCryptoCaptureTests.captureDeterministicCryptoVectors

