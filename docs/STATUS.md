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
  hit tracking, concurrent URL creation, and expiration checks.
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
- Restricted redirect URI matching to the registered callback, with only the
  narrow localhost-port variation needed by the CLI.
- Fixed one-time authorization-code replay handling.
- Enforced future URL expirations, TTL bounds, and HTTP 410 behavior without
  counting hits for expired links.
- Fixed the embedded OAuth template collision that rendered the login page in
  place of the consent page.
- Fixed dynamic repository update SQL construction and the missing production
  Docker configuration copy.
- Pinned the CI Go, goimports, and golangci-lint versions to the local mise
  toolchain.
- Updated the README, deployment notes, API guide, and OpenAPI paths to match
  the running routes.

## Known limitations

- The statistics `timeline` is currently one aggregate point derived from the
  URL total; there is no click-event or daily analytics table yet.
- The rate limiter is process-local and global to URL creation. It is not
  shared across replicas and should be complemented by an edge/API gateway.
- An older Redis-backed limiter remains as unconnected middleware with
  fail-open/no-Redis tests; the running server uses the in-process limiter in
  `internal/server/middleware/rate_limit.go`.
- The current `sessions` schema permits one active refresh session per user.
  Multi-device sessions would need a migration and a session-management model.
- Access JWTs are stateless. Logout immediately revokes refresh sessions, but
  an already-issued access token remains valid until its configured expiry.
- Hit increments are asynchronous; a process shutdown immediately after a
  redirect can lose the last increment.
- Development may use wildcard CORS when `DEBUG=true`; non-debug deployments
  require explicit origins, and `APP_ENV=production` rejects placeholder or
  short JWT secrets. The default deployment still assumes a reverse proxy will
  provide HTTPS. These are deliberate prototype defaults, not a full security
  baseline.
- There is no cleanup job for expired URLs, authorization codes, or old access
  token records.

## Recommended next work

1. Add a stored click-event table and real time-bucketed statistics.
2. Replace the process-local limiter with Redis or an edge limiter and add
   per-user/IP policy tests.
3. Add key rotation/JWK or another managed signing-key strategy before
   issuing tokens outside a single trusted deployment.
4. Decide whether multiple devices are supported, then migrate sessions away
   from the one-row-per-user constraint.
5. Add HTTP integration coverage for malformed redirects, token algorithms,
   CORS policy, pagination bounds, and all documented error responses.
6. Add OpenAPI validation to CI and either wire or remove the disconnected
   Redis limiter.

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
