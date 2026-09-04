# Watchpost Agent

Watchpost Agent collects bounded host evidence and delivers it to an approved Watchpost installation.

## Command line

```sh
watchpost-agent version
watchpost-agent --version
watchpost-agent service status
```

Unknown commands and unsupported options fail with a non-zero exit status.
Run the binary without a subcommand to start the integrated server, or use
`watchpost-agent serve` where that compatibility alias is supported.

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

Release archives are produced with:

```sh
./packaging/build-release.sh v0.1.1
```

The public installer defaults to `~/.local/bin`; pass `--system` as root for
`/usr/local/bin`. Both routes verify the selected archive against
`SHA256SUMS` before installation. The current host collector and service
package support Linux amd64/arm64; other platforms remain a hardening target.

The local interface defaults to `http://127.0.0.1:7335`. It is configured with
`--host`/`--port` (or the legacy single-address `--listen`), with
`WATCHPOST_AGENT_HOST` / `WATCHPOST_AGENT_PORT` / `WATCHPOST_AGENT_LISTEN` and
the defaults applying below them (CLI > environment > default; ports must be
1–65535 and values are trimmed once). `--listen` cannot be combined with
`--host`/`--port`, and a legacy `WATCHPOST_AGENT_LISTEN` conflicts with
`WATCHPOST_AGENT_HOST`/`WATCHPOST_AGENT_PORT` rather than silently picking one.
Binding `--host 0.0.0.0` exposes the interface on all IPv4 interfaces and is
intended only for controlled networks behind a reviewed reverse proxy. The
private state directory defaults to `/var/lib/watchpost-agent` and can be
overridden with `--data-dir` or `WATCHPOST_AGENT_DATA_DIR`.

WP-A02 establishes the restart-safe unpaired application. Installation,
security and pairing arrive in WP-A03–WP-A06.

Install the machine service before pairing (requires root for the first
install, which creates the dedicated `watchpost-agent` account):

```sh
sudo ./watchpost-agent service install
./watchpost-agent service status
./watchpost-agent service logs            # or: ... service logs --follow
sudo ./watchpost-agent service restart
sudo ./watchpost-agent service stop
sudo ./watchpost-agent service start
```

The agent runs as a systemd **system** unit under a dedicated unprivileged
`watchpost-agent` account (nologin, no home). It starts at boot with
`WantedBy=multi-user.target` and does **not** depend on any user login or on
systemd lingering. The binary is installed at `/usr/local/bin/watchpost-agent`
and the data directory is `/var/lib/watchpost-agent` (0700, owned
`watchpost-agent:watchpost-agent`). The full lifecycle family matches the Web
Fleet convention: `install|uninstall|start|stop|restart|status|enable|disable|logs|update|rollback`.

Installation is a transaction. The prior managed unit and installed binary are
preserved, prior systemd enablement and activity are inspected before mutation,
and only exactly-recreatable states are accepted (`enabled`, `enabled-runtime`,
`disabled` × `active`, `inactive`; masked/static/linked/generated/transient/
failed/reloading states are refused before mutation — unmask or stop first).
Rollback restores the exact prior enablement and activity states, distinguishing
persistent from runtime enablement, and reproduces the prior unit and binary.
A byte-identical unit and binary on an already enabled and active service is a
genuine no-op; an unchanged installation that is inactive or disabled receives
only the lifecycle steps needed, and a changed unit or binary is published
transactionally and restarts the service. A failed fresh install is stopped and
disabled while the unit is still loaded, then the unit and binary are removed
and systemd is reloaded. The generated unit carries a versioned SHA-256
managed-unit header, so a hand-modified or foreign unit is never overwritten
or removed silently, and lifecycle commands refuse to operate on it. `status`
reports enabled/running state, PID, version, listen address and a live health
check of the public `GET /healthz` endpoint, and exits nonzero when the service
is failed or missing. An unpaired service is a supported quiet state. Use
`sudo ./watchpost-agent service uninstall` to remove the service registration;
the installed binary and private state are retained for explicit recovery or
reset.

`service install` records the canonical `--host`/`--port` pair in `ExecStart`
so the recorded listener is the runtime listener across restart and reboot;
existing units installed with the legacy `--listen` form keep their listener
until reinstalled, and a bare reinstall or upgrade preserves the recorded
listener. `service install --env-file` additionally records an optional
protected environment file for `WATCHPOST_AGENT_*` variables (exposure, secure
cookies, CIDR policy, setup token file). Only `install`/`upgrade` resolve the
listener flags or `WATCHPOST_AGENT_HOST`/`WATCHPOST_AGENT_PORT`, so malformed
listener environment in the shell never breaks the other lifecycle commands:

```sh
sudo ./watchpost-agent service install                          # 127.0.0.1:7335
sudo ./watchpost-agent service install --host 127.0.0.1 --port 7405
sudo ./watchpost-agent service install --listen 127.0.0.1:7405  # legacy form
sudo ./watchpost-agent service install --env-file /etc/watchpost-agent/watchpost-agent.env
```

The machine configuration file must be an absolute, regular, non-symlink file
with exactly `0600` permissions, owned by `root:root`; it is read by systemd via
`EnvironmentFile=` **before** the process drops to `User=watchpost-agent`, so
the agent cannot rewrite its own machine configuration. Secret values are never
copied into the unit or printed. The recorded environment file is revalidated
before `service start`, `service restart` and `service status`; `service stop`,
`service logs` and `service uninstall` remain available even if it is missing.
Changing it takes effect on `service restart`. Install creates the agent data
directory with owner-only permissions and refuses symlink, non-directory or
group/world-writable paths.

`service update ARTIFACT SHA256` replaces the binary with a checksum-verified
artifact, preserving the prior running/stopped state and enablement, and
retaining rollback metadata so a later `service rollback` restores the previous
version and its operational state. Failed updates recover to the previous
binary before reactivation and surface both the update and recovery failures
when both occur. `service upgrade` (a compatibility alias of install) publishes
the current executable through the same transaction; it does not change
installation identity, local configuration, queue or pairing.

### Least privilege and sandboxing

The agent runs **unprivileged**. It does not require root to read its telemetry
(`/proc/stat`, `/proc/meminfo`, `/proc/loadavg`, `/proc/uptime` and
`statfs()` on filesystems are all available to an unprivileged user). The
generated unit applies `NoNewPrivileges`, `PrivateTmp`, `ProtectSystem=strict`,
`ProtectHome=true`, `ReadWritePaths=/var/lib/watchpost-agent` and
`Restart=on-failure`. Additional systemd isolation controls are added
incrementally and validated against the real telemetry pipeline before they are
retained — a hardening control that breaks CPU/memory/load/filesystem reporting
is never shipped.

The local website requires an email address and a seven-character-or-longer
administrator password. For a headless server, configure the same state without
exposing the password in process arguments:

```sh
printf '%s\n' 'admin@example.com' > /secure/path/agent-email
printf '%s\n' 'your password' > /secure/path/agent-password
chmod 600 /secure/path/agent-email /secure/path/agent-password
./watchpost-agent setup --email-file /secure/path/agent-email --password-file /secure/path/agent-password
./watchpost-agent info --json
```

Remove the temporary files according to your system's secret-handling policy.
The UI binds to loopback by default and enforces authenticated sessions,
same-origin state changes, CSRF tokens, request bounds and login throttling.
Local account passwords use the same versioned PBKDF2-HMAC-SHA256 derivation as
the central server; passwords from older agent builds (custom iterated SHA-256)
must be re-set with `reset` after upgrading. Login is by email and password;
email identities are normalized (lowercase) so case differences cannot create
duplicate accounts or sign into the wrong one.

### First-run setup

Setup over the loopback interface is direct. If agent management is remotely
exposed (a non-loopback listener with `WATCHPOST_AGENT_EXPOSE=1`) or an
operator supplied `WATCHPOST_AGENT_SETUP_TOKEN` / `WATCHPOST_AGENT_SETUP_TOKEN_FILE`,
the first-run form requires a short-lived, single-use bootstrap token printed
once to the agent console (or read from the protected file). Only a hash of the
token is stored; it is consumed atomically with the first administrator's
creation and is never returned by any API. `WATCHPOST_AGENT_SETUP_TOKEN_TTL`
(default 1 hour) bounds its lifetime.

### Atomic local state and audit

Every persistent local change — collector configuration, pairing requests and
approvals, credential rotation, unpair and pending revocation, account
creation and password changes — writes its attributed audit row in the **same
atomic state save** as the change itself. A failed save rolls the whole update
back, leaving both the in-memory state and the on-disk file unchanged, and the
endpoint reports failure rather than success.

Sessions are deliberately held in memory, not in the persistent state, so their
security events cannot share a state save. Login, logout and session
revocation therefore give the audit a truthful durable ordering instead: the
attributed audit entry is persisted **before** the non-failing in-memory
session mutation. If that write fails, no session is created (login), the
session remains valid (logout), or every targeted session remains valid
(revocation), and the endpoint reports failure rather than success.

Exactly one audit entry is emitted per logical operation, attributed to the
authenticated account (the CLI attributes its operations to `cli`), never a
generic actor.

### Local roles

The first setup creates the local `admin` account. Administrators can create
`technician` and `viewer` local accounts from the website's Administrator
panel: `admin` manages accounts, pairing authority, credentials, remote
exposure and destructive lifecycle operations; `technician` can inspect
health, configure collectors and perform normal pairing and recovery tasks;
`viewer` is read-only. Every state-changing local operation is recorded in a
bounded local audit log visible to administrators.

### Remote exposure is experimental

The interface defaults to loopback and is not a hardened internet service.
The ordinary fleet model keeps the UI on `127.0.0.1`: the Agent initiates
telemetry delivery outbound to central Watchpost, and administrators reach a
single Agent's UI safely through an SSH tunnel without publishing it to the
network:

```sh
ssh -L 7335:127.0.0.1:7335 operator@monitored-host
```

Then open `http://127.0.0.1:7335` in the local browser. Binding a non-loopback
address requires an explicit `WATCHPOST_AGENT_EXPOSE=1` opt-in and prints a
prominent warning. For any remote use terminate HTTPS at a reviewed reverse
proxy, set `WATCHPOST_AGENT_SECURE_COOKIES=1`, list the proxy in
`WATCHPOST_AGENT_TRUSTED_PROXIES` (comma-separated CIDRs or addresses — for a
local proxy use `127.0.0.0/8`) so forwarded scheme/host are honoured only when
the immediate peer is that trusted proxy, and restrict clients with
`WATCHPOST_AGENT_ALLOW_CIDRS` / `WATCHPOST_AGENT_DENY_CIDRS`. Forwarded headers
from any untrusted peer are ignored, and when a client CIDR policy is active an
unresolvable client address fails closed. The first-run setup requires a
bootstrap token whenever the interface is remotely exposed or an operator
supplied one (see "First-run setup"). Review the local audit log. Loopback
binding remains the documented recovery path: with no client policy configured,
requests are never blocked on address resolution. Remote Agent exposure stays
experimental; never assume `127.0.0.1` on the Agent host refers to another
machine, and do not present one publicly exposed Agent as representing the
fleet.

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

Rotate the post-scoped credential from either the lifecycle panel or CLI:

```sh
./watchpost-agent rotate
```

Moving an installation to another post is deliberately an unpair/new-approval
journey. Archiving or deleting a post never silently moves remote authority.
