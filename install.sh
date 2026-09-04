#!/bin/sh
# install.sh installs the watchpost-agent binary only. Machine-service
# configuration (systemd unit, dedicated unprivileged account,
# /var/lib/watchpost-agent, protected configuration) is owned by the Go CLI:
# `sudo watchpost-agent service install`. With --system the binary is installed
# to /usr/local/bin and the canonical Go service installer is invoked; the
# shell script contains no systemd logic. Set WATCHPOST_AGENT_SKIP_SERVICE_INSTALL=1
# to skip the service configuration step (headless/non-systemd contexts and
# install-script smoke tests).
set -eu
system=0
version=${WATCHPOST_AGENT_VERSION:-latest}
while [ "$#" -gt 0 ]; do case "$1" in --system) system=1;; --version) shift; version=${1:?version required};; --help) echo "usage: install.sh [--system] [--version VERSION]"; exit 0;; *) echo "unknown option: $1" >&2; exit 2;; esac; shift; done
if [ "$system" -eq 1 ]; then [ "$(id -u)" -eq 0 ] || { echo "--system requires root" >&2; exit 1; }; destination=/usr/local/bin/watchpost-agent; else [ "$(id -u)" -ne 0 ] || { echo "run without sudo or pass --system" >&2; exit 1; }; destination=${WATCHPOST_AGENT_INSTALL_DIR:-"$HOME/.local/bin"}/watchpost-agent; fi
os=$(uname -s | tr '[:upper:]' '[:lower:]'); arch=$(uname -m); case "$arch" in x86_64|amd64) arch=amd64;; aarch64|arm64) arch=arm64;; *) echo "unsupported architecture: $arch" >&2; exit 1;; esac
[ "$os" = linux ] || { echo "host collection currently supports Linux only" >&2; exit 1; }
if [ "$version" = latest ]; then version=$(curl -fsSL https://api.github.com/repos/watchpost-cv/watchpost-agent/releases/latest | sed -n 's/.*"tag_name":[[:space:]]*"\([^"]*\)".*/\1/p' | head -1); fi
[ -n "$version" ] || { echo "could not resolve release version" >&2; exit 1; }
asset="watchpost-agent-${version}-${os}-${arch}.tar.gz"; base="https://github.com/watchpost-cv/watchpost-agent/releases/download/${version}"
temporary=$(mktemp -d); trap 'rm -rf "$temporary"' EXIT INT TERM; curl -fsSL "$base/$asset" -o "$temporary/$asset"; curl -fsSL "$base/SHA256SUMS" -o "$temporary/SHA256SUMS"; (cd "$temporary" && grep "  $asset$" SHA256SUMS | sha256sum -c -); tar -xzf "$temporary/$asset" -C "$temporary"; mkdir -p "$(dirname "$destination")"; install -m 0755 "$temporary/watchpost-agent" "$destination"
echo "Installed $destination"
if [ "$system" -eq 1 ] && [ "${WATCHPOST_AGENT_SKIP_SERVICE_INSTALL:-0}" != 1 ]; then
  if command -v systemctl >/dev/null 2>&1; then
    echo "Configuring the watchpost-agent machine service..."
    "$destination" service install
  else
    echo "systemd not found; run 'sudo watchpost-agent service install' on a systemd host to configure the service."
  fi
fi
if [ "$system" -eq 0 ]; then case ":$PATH:" in *":$(dirname "$destination"):"*) :;; *) echo "Add $(dirname "$destination") to PATH.";; esac; fi
