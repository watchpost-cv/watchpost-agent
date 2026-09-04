# Watchpost Agent {{VERSION}}

Watchpost Agent {{VERSION}} is a {{RELEASE_KIND}}.

## What this release is

- A lightweight companion agent that runs on the monitored host and delivers
  telemetry to a Watchpost server over an outbound, queued connection.
- Linux amd64 and arm64 release archives, plus `SHA256SUMS`.

## Operator responsibilities

- Pair the agent with a Watchpost server before relying on it for delivery.
- Read the known limitations before relying on Watchpost Agent in production.
- Watchpost Agent is a public preview for evaluation and early self-hosting;
  it is not claimed to be production-proven or battle-proven.

## Installation

- https://watchpost.cv/agent-install.sh (per-user)
- https://watchpost.cv/agent-download.sh (download the archive)
- https://watchpost.cv/agent-update.sh (upgrade an existing install)