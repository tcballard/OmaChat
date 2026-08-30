#!/bin/sh
set -eu

version=$(tr -d '\r\n' < VERSION)
profile='bitchat-swift-v1.7.1'
swift='9edb7c26ef7bdcf3bb29e7907b38997f8d5cd0fa'
android='93e9594bad3e537b4ec6fd096c0fde7533f22e74'
omarchy='13f18b2cb7286fb54f87daf571a031aa6af3d8f0'
target_dir=${CARGO_TARGET_DIR:-target}
check_dir=$(mktemp -d)
trap 'rm -rf "$check_dir"' EXIT HUP INT TERM

for binary in omachat omachatd omachat-ctl; do
    expected="$binary $version (profile=$profile; swift=$swift; android=$android; omarchy=$omarchy)"
    printf '%s\n' "$expected" > "$check_dir/expected"

    if ! "$target_dir/debug/$binary" --version \
        > "$check_dir/stdout" 2> "$check_dir/stderr"; then
        printf 'version contract failed for %s: non-zero exit\n' "$binary" >&2
        exit 1
    fi

    if ! cmp -s "$check_dir/expected" "$check_dir/stdout"; then
        printf 'version contract failed for %s: stdout differs\n' "$binary" >&2
        diff -u "$check_dir/expected" "$check_dir/stdout" >&2 || true
        exit 1
    fi

    if [ -s "$check_dir/stderr" ]; then
        printf 'version contract failed for %s: stderr is not empty\n' "$binary" >&2
        exit 1
    fi
done

printf 'binary version contract passed\n'
