# Project status

Snapshot: 2026-08-30

Maigo is a working prototype with a complete local path from database setup to
CLI/API use. It is not yet a production-ready hosted service.

## Verified in this audit

- Reproducible local tools are pinned in [`mise.toml`](../mise.toml): Go
  1.23.12, Air 1.61.7, golangci-lint 1.64.5, migrate 4.18.3, GoReleaser 2.18.0,
  and goimports.
- `mise exec -- go test -short ./internal/...` passes.
- `mise exec -- go vet ./...` passes.
- `mise exec -- golangci-lint run --timeout=5m` passes.
- The PostgreSQL integration suite passes against an isolated PostgreSQL 16
  container, including authentication, OAuth/PKCE, refresh rotation, logout,
  multi-device sessions, refresh-session cleanup, hit tracking, click
  retention, concurrent URL creation, and expiration checks.
- Prometheus-format operational counters cover redirects, click persistence,
  click retention, and refresh-session cleanup; the metrics endpoint is
  available for scraping.
- `mise exec -- goreleaser check` passes.
- `Dockerfile.production` builds and the resulting image runs its CLI smoke
  command on the current host architecture.
- CLI help works for the root, server, and migration commands without trying to
  execute a command or reporting a false `pflag: help requested` error.

## What was completed

- Removed the hard-coded OAuth authorization-code user and bind codes to the
  authenticated browser user.
- Made PKCE mandatory for authorization requests and limited it to S256.
- Replaced plaintext password storage/comparison with bcrypt.
- Added typed HS256 access/refresh tokens, issuer/audience checks, hashed
  refresh sessions, one-time refresh rotation, and real logout/revocation.
- Added an HMAC signing-key ring with `kid` headers, retained-key verification,
  and legacy no-`kid` token compatibility for controlled rotation.
- Restricted redirect URI matching to the registered callback, with only the
  narrow localhost-port variation needed by the CLI.
- Fixed one-time authorization-code replay handling.
- Enforced future URL expirations, TTL bounds, and HTTP 410 behavior without
  counting hits for expired links.
- Fixed the embedded OAuth template collision that rendered the login page in
  place of the consent page.
- Fixed dynamic repository update SQL construction and the missing production
  Docker configuration copy.
- Added a persisted click-event ledger, transactional aggregate hit updates,
  and UTC day-bucketed URL statistics.
- Added configurable click-event retention with batched cleanup, graceful
  server shutdown, and operational counters for tracking and cleanup failures.
- Removed the one-session-per-user constraint, added multi-device refresh
  sessions, scheduled expired-session cleanup, and cleanup outcome metrics.
- Pinned the CI Go, goimports, and golangci-lint versions to the local mise
  toolchain.
- Updated the README, deployment notes, API guide, and OpenAPI paths to match
  the running routes.

## Known limitations

- Click-event retention defaults to 90 days and is configurable. Retention
  deletes event rows but intentionally preserves lifetime URL hit totals.
- Existing aggregate hit counts are not backfilled into click events because
  their original click times are unavailable; legacy URLs may therefore have
  a timeline total lower than their aggregate `hits` value.
- Redis-backed rate limiting is now available for the running server. It uses
  an atomic fixed-window script and fail-closed behavior by default when
  enabled. With Redis disabled, the fallback is a bounded per-client
  in-process limiter and is not shared across replicas. Forwarded client-IP
  headers are ignored unless explicitly allowed by `TRUSTED_PROXIES`.
- Refresh sessions are stored per login/client and expired rows are removed by
  the scheduled cleanup worker. The JSON logout endpoint revokes all sessions
  for a user; OAuth token revocation remains token-specific.
- Access JWTs are stateless. Logout immediately revokes refresh sessions, but
  an already-issued access token remains valid until its configured expiry.
- The rotating key ring is HMAC-based and configuration-distributed; it does
  not provide a public JWKS endpoint because symmetric signing secrets must not
  be published.
- Click recording is synchronous and transactional with the aggregate hit
  update. If the tracking write fails, the redirect still proceeds and the
  event is logged and counted rather than retried through a durable queue.
- Metrics are process-local counters that reset on restart; `/metrics` has no
  built-in authentication and must be kept on a private network path or behind
  an authenticated proxy.
- Development may use wildcard CORS when `DEBUG=true`; non-debug deployments
  require explicit origins, and `APP_ENV=production` rejects placeholder
  database, Redis, or short/known JWT secrets. The default deployment still
  assumes a reverse proxy will provide HTTPS. These are deliberate prototype
  defaults, not a full security baseline.
- There is no cleanup job for expired URLs, authorization codes, or old access
  token records; refresh-session cleanup and click-event cleanup are covered by
  scheduled workers.

## Recommended next work

1. Add a durable click-event outbox/retry path if tracking every redirect
   across database outages is a hard requirement.
2. Make Redis or an equivalent edge limiter part of the required topology for
   horizontally scaled deployments, and add per-user/IP policy tests.
3. Add a managed secret distribution/control-plane integration for the HMAC
   key ring before operating many independent deployments.
4. Add explicit session listing/device metadata and a user-facing per-device
   management API if device-specific session management is required.
5. Add HTTP integration coverage for malformed redirects, token algorithms,
   CORS policy, pagination bounds, and all documented error responses.
6. Add OpenAPI validation to CI and include Redis-backed integration coverage
   in the normal production-like test profile.

## Running the checks

Unit-only:

```bash
make setup
make test-unit
make lint
```

Full local integration run using an isolated database:

```bash
DB_PORT=55432 DB_NAME=maigo_test DB_USER=postgres DB_PASSWORD=password \
  docker compose -p maigo-audit up -d postgres
MAIGO_TEST_DATABASE_URL='postgres://postgres:password@localhost:55432/maigo_test?sslmode=disable' \
  mise exec -- go test ./tests/...
```

The audit database can be stopped later with:

```bash
docker compose -p maigo-audit stop postgres
```
