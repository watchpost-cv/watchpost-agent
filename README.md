# Watchpost Agent

Watchpost Agent is the separately installed machine-monitoring companion for
Watchpost. It provides an embedded local website for normal setup and an
equivalent CLI for headless servers, SSH, automation and recovery.

The accepted architecture is documented in [ARCHITECTURE.md](ARCHITECTURE.md)
and the ordered implementation programme in [PLAN.md](PLAN.md).

Compile the Nift interface and agent:

```sh
nift build
go build -o watchpost-agent ./cmd/watchpost-agent
./watchpost-agent
```

The local interface defaults to `http://127.0.0.1:8090`. The private state
directory defaults to `~/.local/share/watchpost-agent` and can be overridden
with `--data-dir` or `WATCHPOST_AGENT_DATA_DIR`.

WP-A02 establishes the restart-safe unpaired application. Installation,
security and pairing arrive in WP-A03–WP-A06.
