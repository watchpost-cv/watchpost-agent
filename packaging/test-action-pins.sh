#!/bin/sh
# test-action-pins.sh proves scripts/action-pins.sh rejects every class of
# mutable or unpinned action reference while accepting the current pinned
# workflows. It never modifies the real workflow files; mutations run against
# temporary copies under mktemp.
set -eu
cd "$(dirname "$0")/.."

V=packaging/action-pins.sh
DIR=.github/workflows

"$V" "$DIR" >/dev/null || { echo "real workflows rejected by action-pins" >&2; exit 1; }

tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT

expect_reject() {
  name=$1
  file=$2
  if "$V" "$file" >/dev/null 2>&1; then
    echo "action-pins accepted mutable reference: $name" >&2
    exit 1
  fi
}

cp "$DIR/ci.yml" "$tmp/ci.yml"
BASE="$tmp/ci.yml"

sed 's|actions/checkout@[0-9a-f]\{40\}|actions/checkout@v4|' "$BASE" > "$tmp/m1.yml"
expect_reject "major-version tag v4" "$tmp/m1.yml"

sed 's|actions/checkout@[0-9a-f]\{40\}|actions/checkout@main|' "$BASE" > "$tmp/m2.yml"
expect_reject "branch name" "$tmp/m2.yml"

sed 's|actions/setup-go@[0-9a-f]\{40\}|actions/setup-go@v5.0.0|' "$BASE" > "$tmp/m3.yml"
expect_reject "float tag v5.0.0" "$tmp/m3.yml"

sed 's|actions/setup-go@[0-9a-f]\{40\}|actions/setup-go@abcd1234|' "$BASE" > "$tmp/m4.yml"
expect_reject "short SHA" "$tmp/m4.yml"

sed 's|actions/checkout@[0-9a-f]\{40\}|actions/checkout|' "$BASE" > "$tmp/m5.yml"
expect_reject "missing ref" "$tmp/m5.yml"

echo "action-pins negative tests: PASS"