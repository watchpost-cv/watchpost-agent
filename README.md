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

Release archives are produced with:

```sh
./packaging/build-release.sh v0.1.0
```

The public installer defaults to `~/.local/bin`; pass `--system` as root for
`/usr/local/bin`. Both routes verify the selected archive against
`SHA256SUMS` before installation. The current host collector and service
package support Linux amd64/arm64; other platforms remain a hardening target.

The local interface defaults to `http://127.0.0.1:8090`. The private state
directory defaults to `~/.local/share/watchpost-agent` and can be overridden
with `--data-dir` or `WATCHPOST_AGENT_DATA_DIR`.

WP-A02 establishes the restart-safe unpaired application. Installation,
security and pairing arrive in WP-A03–WP-A06.

Install the per-user service before pairing:

```sh
./watchpost-agent service install
./watchpost-agent service status
./watchpost-agent service logs            # or: ... service logs --follow
./watchpost-agent service restart
./watchpost-agent service stop
./watchpost-agent service start
```

`watchpost-agent service ...` is the canonical form; the top-level
`install`/`upgrade`/`status`/`start`/`stop`/`restart`/`logs`/`uninstall`
commands remain as compatibility aliases.

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
`./watchpost-agent service uninstall` to remove the service and installed
binary; private state is retained for explicit recovery or reset. Uninstall
stops and disables the service only after verifying safe states and restores
the unit atomically if the final reload fails.

`service install --listen` and `service install --env-file` record the agent's
listen address and an optional protected environment file for
`WATCHPOST_AGENT_*` variables (exposure, secure cookies, CIDR policy, setup
token file):

```sh
./watchpost-agent service install --env-file /absolute/protected/agent.env
```

The environment file must be an absolute, regular, non-symlink file with
exactly `0600` permissions, owned by the invoking user; it is referenced by the
unit's `EnvironmentFile=` and its path is recorded in the integrity-checked
managed metadata. Secret values are never copied into the unit or printed. The
recorded environment file is revalidated before `service start`, `service
restart` and `service status`; `service stop`, `service logs` and `service
uninstall` remain available even if it is missing. Changing it takes effect on
`service restart`. Install creates the agent data directory with owner-only
permissions and refuses symlink, non-directory or group/world-writable paths.

`service upgrade` (or `upgrade`) after replacing the downloaded executable
publishes the new binary through the same transaction as install: the prior
unit and binary are preserved for rollback, a byte-identical unit and binary on
an already enabled and active service is a genuine no-op, and a changed binary
is published transactionally and restarts the service. It does not change
installation identity, local configuration, queue or pairing, and preserves the
installed listen address and environment file unless you pass an explicit
`--listen`/`--env-file` override.

### Persistence and lingering

Once installed, the service runs independently of the terminal that launched
it: closing the terminal does not stop it. A systemd user service is tied to
your OS user's user manager, so it normally starts when that user manager
starts (for example at your first login after boot). Unattended boot or
continuing to run after you log out may require lingering for your user:

```sh
loginctl show-user "$USER" -p Linger
loginctl enable-linger "$USER"   # explicit host-level choice
```

Enable lingering deliberately: it keeps your user's services running without a
login session and changes what runs unattended. The unit records the absolute
path of the `watchpost-agent` executable at install time (in
`~/.local/lib/watchpost-agent/`); moving or deleting that binary will break the
service.

`--system` is **not currently supported**: the previous system-wide mode ran
the agent's web service (setup, login, configuration, pairing, rotation, reset
and account-management endpoints) as root, which is not an acceptable default.
A dedicated unprivileged service account design is a documented follow-up.

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
ssh -L 8090:127.0.0.1:8090 operator@monitored-host
```

Then open `http://127.0.0.1:8090` in the local browser. Binding a non-loopback
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
