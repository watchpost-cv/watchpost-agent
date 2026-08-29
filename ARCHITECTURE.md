# Watchpost Agent architecture

Status: accepted at WP-A01 on 2026-08-28.

## Boundary

Watchpost Agent is a separate program from Watchpost and has its own embedded
website. It is installed before it is paired. Its website and CLI are equal
control surfaces over one application service and one persistent state model.

The website is the normal interactive experience. The CLI is required for
headless servers, configuration management, SSH-only recovery and environments
where a browser is unavailable.

## Responsibilities

The agent owns:

- an opaque installation UUID;
- local UI authentication and CSRF state;
- the approved Watchpost connection and credential;
- enabled local collectors and their bounded configuration;
- a durable bounded delivery queue;
- local connection, collection and delivery diagnostics.

Watchpost owns posts, pairing approval, history, rules, alerts, incidents and
fleet policy. A collector is an implementation inside the agent, not a second
user-managed inventory object.

## Default exposure

The embedded UI listens on loopback only. Non-loopback access is explicitly
experimental: binding a non-loopback interface requires `WATCHPOST_AGENT_EXPOSE=1`
and prints a prominent warning. Remote use must terminate HTTPS at a reviewed
reverse proxy, enable secure cookies, list the proxy in
`WATCHPOST_AGENT_TRUSTED_PROXIES` so forwarded headers are believed only from a
trusted immediate peer, restrict client CIDRs (failing closed when an address
policy cannot resolve the client), and rely on the local role model and audit
log. First-run setup over a non-loopback interface (or with an operator-supplied
token) requires a short-lived single-use bootstrap token printed once at
startup; only a hash is stored and it is consumed atomically with the first
administrator's creation. Forwarded headers are never trusted from an untrusted
peer. Pairing and delivery use HTTPS except when both programs communicate over
loopback for local development.

## Local roles

The first setup creates a local `admin` with a chosen email address. `admin`
manages local accounts (technician/viewer), pairing authority, credentials,
remote exposure and destructive lifecycle operations; `technician` inspects
health, configures collectors and performs normal pairing and recovery; `viewer`
is read-only. Login is by email and password, and identities are normalized
(lowercase) so case differences cannot collide. Local accounts are independent
of Watchpost sessions: the agent must remain manageable when Watchpost is
unavailable. State-changing local operations are recorded in a bounded local
audit log. Local password hashes use the same versioned PBKDF2-HMAC-SHA256
derivation as the central server; hashes from older agent builds must be
re-established with `reset`.

## Lifecycle

```text
installed -> pairing requested -> paired -> healthy
    ^              |                |         |
    |              v                v         v
 unpaired       expired          rejected   stale/offline
```

Unpairing removes connection authority without removing the program. Resetting
removes local configuration. Uninstalling stops and removes the service and
program. Those operations must never be conflated.
