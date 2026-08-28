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

Install the per-user service before pairing:

```sh
./watchpost-agent install
./watchpost-agent status
```

For a deliberate machine-wide service, run as an appropriately privileged
administrator:

```sh
sudo ./watchpost-agent install --system
```

Installation is idempotent and atomically replaces the installed executable,
then restarts the service. An unpaired service is a supported quiet state. Use
`./watchpost-agent uninstall` (or `--system`) to remove the service and installed
binary; private state is retained for explicit recovery or reset.

The local website requires a seven-character-or-longer administrator password.
For a headless server, configure the same state without exposing the password
in process arguments:

```sh
printf '%s\n' 'your password' > /secure/path/agent-password
chmod 600 /secure/path/agent-password
./watchpost-agent setup --password-file /secure/path/agent-password
./watchpost-agent info --json
```

Remove the temporary password file according to your system's secret-handling
policy. The UI binds to loopback by default and enforces authenticated sessions,
same-origin state changes, CSRF tokens, request bounds and login throttling.

Pair from the local website, or use the equivalent flow on a headless server:

```sh
./watchpost-agent pair --server https://watchpost.example.net
./watchpost-agent pair-status
```

The first command prints a short phrase. Approve that exact phrase in Watchpost,
then run `pair-status` to retrieve and store the one-time credential. Both
control surfaces use the same private state file.

After approval, `pair-status` (or the website's **Check approval** button)
retrieves the credential and immediately sends CPU, memory, root-filesystem and
uptime signals. The running service repeats delivery every minute.

Configure the same collectors from the local website or on a server:

```sh
./watchpost-agent configure --interval 60 \
  --cpu=true --memory=true --load=true --uptime=true \
  --filesystems /,/data
```

Intervals are bounded to 15–3600 seconds and filesystem paths must be unique,
absolute, and limited to eight.
