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

The embedded UI listens on loopback only. Non-loopback access must be explicit,
authenticated and documented. Pairing and delivery use HTTPS except when both
programs communicate over loopback for local development.

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
