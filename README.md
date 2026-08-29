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

Use `./watchpost-agent upgrade` after replacing the downloaded executable.
It atomically replaces the stable installed binary and restarts the service
without changing installation identity, local configuration, queue or pairing.

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
Binding a non-loopback address requires an explicit
`WATCHPOST_AGENT_EXPOSE=1` opt-in and prints a prominent warning. For any
remote use terminate HTTPS at a reviewed reverse proxy, set
`WATCHPOST_AGENT_SECURE_COOKIES=1`, list the proxy in
`WATCHPOST_AGENT_TRUSTED_PROXIES` (comma-separated CIDRs or addresses — for a
local proxy use `127.0.0.0/8`) so forwarded scheme/host are honoured only when
the immediate peer is that trusted proxy, and restrict clients with
`WATCHPOST_AGENT_ALLOW_CIDRS` / `WATCHPOST_AGENT_DENY_CIDRS`. Forwarded headers
from any untrusted peer are ignored, and when a client CIDR policy is active an
unresolvable client address fails closed. The first-run setup requires a
bootstrap token whenever the interface is remotely exposed or an operator
supplied one (see "First-run setup"). Review the local audit log. Loopback
binding remains the documented recovery path: with no client policy configured,
requests are never blocked on address resolution.

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
