#!/bin/sh
set -eu
root=$(CDPATH= cd -- "$(dirname "$0")/.." && pwd); go_bin=${GO_BIN:-go}; nift_bin=${NIFT_BIN:-nift}; cd "$root"
"$nift_bin" build --all
"$go_bin" test ./...
"$go_bin" test -race ./...
"$go_bin" vet ./...
"$go_bin" build -o "${TMPDIR:-/tmp}/watchpost-agent-gate" ./cmd/watchpost-agent
sh -n install.sh packaging/build-release.sh
echo "Watchpost Agent local hardening gate passed"
