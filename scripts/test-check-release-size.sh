#!/bin/sh
set -eu

script_directory=$(CDPATH= cd "$(dirname "$0")" && pwd)
checker=$script_directory/check-release-size.sh
maximum_total_bytes=$((10 * 1024 * 1024))
test_directory=$(mktemp -d "${TMPDIR:-/tmp}/omachat-release-size-test.XXXXXX")

cleanup() {
  rm -rf "$test_directory"
}
trap cleanup EXIT HUP INT TERM

fail() {
  echo "release-size-test: $*" >&2
  exit 1
}

make_binary() {
  binary_path=$1
  binary_bytes=$2
  dd if=/dev/zero of="$binary_path" bs=1 count=0 seek="$binary_bytes" 2>/dev/null
  chmod +x "$binary_path"
}

prepare_case() {
  case_directory=$1
  omachatd_bytes=$2
  omachat_bytes=$3
  omachat_ctl_bytes=$4
  mkdir -p "$case_directory/release"
  make_binary "$case_directory/release/omachatd" "$omachatd_bytes"
  make_binary "$case_directory/release/omachat" "$omachat_bytes"
  make_binary "$case_directory/release/omachat-ctl" "$omachat_ctl_bytes"
}

valid_directory=$test_directory/valid
valid_output=$test_directory/valid.output
prepare_case "$valid_directory" 1024 2048 4096
if ! CARGO_TARGET_DIR=$valid_directory "$checker" >"$valid_output" 2>&1; then
  cat "$valid_output" >&2
  fail "a valid aggregate was rejected"
fi
grep -Fq 'aggregate = 7168 bytes' "$valid_output" ||
  fail "the valid aggregate measurement was not reported"
echo 'release-size-test: valid aggregate passes'

missing_directory=$test_directory/missing
missing_output=$test_directory/missing.output
mkdir -p "$missing_directory/release"
make_binary "$missing_directory/release/omachatd" 1
make_binary "$missing_directory/release/omachat" 1
if CARGO_TARGET_DIR=$missing_directory "$checker" >"$missing_output" 2>&1; then
  fail "a missing installed binary was accepted"
fi
grep -Fq "missing executable $missing_directory/release/omachat-ctl" "$missing_output" ||
  fail "the missing-binary failure was not reported"
echo 'release-size-test: missing binary fails'

ceiling_directory=$test_directory/ceiling
ceiling_output=$test_directory/ceiling.output
prepare_case "$ceiling_directory" "$((maximum_total_bytes - 2))" 1 1
if ! CARGO_TARGET_DIR=$ceiling_directory "$checker" >"$ceiling_output" 2>&1; then
  cat "$ceiling_output" >&2
  fail "an aggregate exactly at the ceiling was rejected"
fi
grep -Fq "aggregate = $maximum_total_bytes bytes" "$ceiling_output" ||
  fail "the exact-ceiling aggregate measurement was not reported"
echo 'release-size-test: exact ceiling passes'

oversize_directory=$test_directory/oversize
oversize_output=$test_directory/oversize.output
prepare_case "$oversize_directory" "$((maximum_total_bytes - 1))" 1 1
if CARGO_TARGET_DIR=$oversize_directory "$checker" >"$oversize_output" 2>&1; then
  fail "an aggregate above the ceiling was accepted"
fi
grep -Fq 'aggregate executable size exceeds the 10 MiB ceiling' "$oversize_output" ||
  fail "the oversize failure was not reported"
echo 'release-size-test: aggregate above ceiling fails'
