# Watchpost Agent automation

Example session workflow:

```sh
printf '%s\n' '{"email":"admin@example.invalid","password":"REDACTED"}' > /tmp/watchpost-agent-login.json
chmod 600 /tmp/watchpost-agent-login.json
# Choose the login command from the generated matrix, then persist the returned session:
watchpost-agent <login-resource> <login-verb> --input /tmp/watchpost-agent-login.json --session-file "$HOME/.config/watchpost-agent/session.json" --json
```

For subsequent operations use JSON input/stdin, `--json`, bounded `--timeout`, pagination/filter `--query`, and a stable `--request-id`. When an operation declares idempotency support, the request ID is also sent as the idempotency key. Destructive commands require `--yes`. Distributed commands report partial failure instead of collapsing it into success.

See [`CLI.md`](CLI.md) and the generated matrix for exact commands.
