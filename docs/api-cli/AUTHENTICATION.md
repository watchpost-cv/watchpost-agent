# Watchpost Agent authentication

Use `--session-file` for the local management HTTP API. Existing direct machine-state commands (`setup`, `info`, `pair`, `pair-status`, `configure`, `rotate`, `unpair`, `reset`) remain first-class local commands.

The default browser session cookie is `watchpost_agent_session` and state-changing session requests use `X-Watchpost-Agent-CSRF`. Session files are JSON credential containers created/read by the common CLI and written with mode `0600`; on Unix, token/session files accessible by group or others are rejected. Passwords and tokens are supplied through protected files or JSON input, never command-line credential flags.

Human accounts remain installation-local. Cluster/service identities are separate from human sessions wherever applicable.
