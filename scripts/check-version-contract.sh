#!/bin/sh
set -eu

version=$(tr -d '\r\n' < VERSION)
target_dir=${CARGO_TARGET_DIR:-target}
check_dir=$(mktemp -d)
trap 'rm -rf "$check_dir"' EXIT HUP INT TERM

for binary in omachat omachatd omachat-ctl; do
    expected="$binary $version (hosted-v1; ipc=3)"
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
