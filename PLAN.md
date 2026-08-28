# Watchpost Agent implementation plan

- **WP-A01 — architecture — complete:** freeze posts, monitoring methods, agent, collector,
  install-before-pair and dual web/CLI boundaries.
- **WP-A02 — application — complete:** Go executable, durable state and
  embedded Nift UI; installation identity survives restart.
- **WP-A03 — installation — complete:** safe per-user/system installation in
  an unpaired state, atomic upgrades and service lifecycle.
- **WP-A04 — local security — complete:** loopback default, authenticated
  session, Origin, CSRF, rate limits and equivalent CLI operations.
- **WP-A05 — pairing v2 — complete:** request/approval, matching phrase, expiry, polling,
  credential issue and rotation.
- **WP-A06 — complete journey — complete:** web and CLI pairing, first telemetry, restart
  recovery and explicit failure states.

Later checkpoints add configurable collectors, dense fleet visualisation,
device methods, lifecycle completion, release packaging and hardening.
