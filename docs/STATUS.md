# Project status

Snapshot: 2026-08-30

Maigo is now being treated as Maigo Core 1.0: a deliberately small,
self-hosted, single-instance shortener. The previous production-hardening work
is preserved on the `codex/production-hardening` branch for reference; this
branch is the simplified runtime.

## Current implementation

- SQLite persistence in one file with automatic idempotent schema bootstrap.
- One API key for management operations; redirects and metadata are public.
- Random Base62 codes and custom Base62 aliases.
- Future expiration by TTL or RFC3339 timestamp; expired redirects return 410.
- Lifetime hit count incremented atomically on successful redirects.
- Create, list, inspect, stats, and delete through the HTTP API and CLI.
- Local stdio MCP server with five matching tools: shorten, list, inspect,
  stats, and delete.
- `PUBLIC_URL` is the canonical generated-link origin.
- One-container Compose deployment, persistent data volume, and SQLite backup
  and restore scripts.

## Verification

The Core suite is self-contained and does not need Postgres, Redis, a browser,
or a network service:

```bash
mise exec -- go test ./...
mise exec -- go vet ./...
CGO_ENABLED=0 mise exec -- go build ./cmd/maigo
```

The HTTP integration suite covers unauthenticated rejection, API-key headers,
custom-code conflicts, public inspection, redirects, hit counting, listing,
deletion, and expiration validation. The MCP test connects an in-memory MCP
client to the registered tools.

## Stopping point

Core is complete enough for a small self-hosted deployment when the operator
can run the container with `API_KEY`, `PUBLIC_URL`, and a persistent volume;
use the CLI without browser/account setup; launch `maigo mcp` from an MCP host;
put one DNS record and an external TLS proxy in front; and restore a tested
SQLite backup.

## Known limits

- There is one owner and one API key. Rotate the key by changing configuration
  and restarting the service; do not expose management endpoints broadly.
- SQLite and the application are intended to run as one instance. There is no
  horizontal scaling or distributed lock/rate-limit layer.
- Stats contain a lifetime count only. Core does not retain click events,
  timelines, referrer data, or per-user analytics.
- TLS, DNS, WAF policy, request rate limiting, and abuse controls belong at an
  external edge proxy.
- Backups are operator-run; the included scripts stop the service briefly to
  produce a consistent archive.
- The MCP process calls the HTTP API and therefore needs reachability to the
  configured `PUBLIC_URL`.

## Deferred by design

OAuth, browser consent, accounts, JWTs, refresh sessions, Redis, distributed
rate limiting, multi-tenant ownership, click-event retention, application-
managed domains, and application-managed certificates are not part of Core.
They should only be reconsidered as a separate product decision with a real
operational need.
