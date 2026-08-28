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

- **WP-A07 — post-owned connections — complete:** expose installed agents as monitoring
  details beneath posts; never create duplicate inventory.
- **WP-A08 — collector profiles — complete:** validated CPU, memory, filesystem, load and
  uptime configuration through equal website and CLI operations.
- **WP-A09 — reliable delivery — complete:** bounded durable queue, ordered replay,
  exponential retry and explicit loss across restart.
- **WP-A10 — lifecycle and health — complete:** healthy, stale, offline, partial, rejected,
  revoked and unpaired states plus revoke, unpair and reset operations.
- **WP-A11 — dense survey — complete:** compact visual health bars and trends across many
  posts, with accessible numeric values and responsive layouts.
- **WP-A12 — policy-aware status — complete:** connect signals to starter rules and show
  safe, warning, critical, unknown and maintenance state without hiding cause.
- **WP-A13 — central checks — complete:** scheduled HTTP, TCP, TLS, DNS and ICMP methods.
- **WP-A14 — device methods:** durable read-only SNMP profiles and adapter
  boundary for non-host devices.
- **WP-A15 — broader device evidence:** UPS, PDU, environmental and storage
  profiles with explicit quality and freshness.
- **WP-A16 — lifecycle completion:** upgrade, credential rotation, move,
  archive, delete, reset and uninstall journeys.
- **WP-A17 — packaging and scale:** release artifacts, installers, many-post
  dogfood and bounded resource evidence.
- **WP-A18 — hardening:** recovery, hostile input, accessibility, platform and
  release evidence without overstating production readiness.
