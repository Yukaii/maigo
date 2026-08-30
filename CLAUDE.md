# Maigo contributor guide

Maigo is a terminal-first URL shortener prototype written in Go. The browser
surface exists to complete the OAuth authorization-code flow; URL management is
primarily exposed through the API and CLI.

Read [`docs/STATUS.md`](docs/STATUS.md) for the current audit, verified
commands, known limitations, and next work. The project is useful for local
evaluation but should not be treated as a production-ready hosted service.

## Stack and layout

- Go 1.23.12, managed locally with mise
- Gin HTTP server and Cobra CLI
- PostgreSQL via pgxpool and SQL migrations
- JWT access tokens plus database-backed, rotating refresh sessions
- OAuth 2.0 authorization code flow with mandatory PKCE S256 for the CLI
- `cmd/maigo`: executable entry point
- `internal/server`: HTTP routes, handlers, middleware, and OAuth templates
- `internal/oauth`: authorization-code, PKCE, and token logic
- `internal/database`: connection, repositories, models, and migrations
- `internal/shortener`: URL/code validation and generation
- `tests/integration_test.go`: PostgreSQL-backed HTTP integration suite

## Local workflow

Install the pinned toolchain and dependencies:

```bash
make setup
```

Run the fast checks:

```bash
make fmt-check
make lint
make test-unit
```

Run integration tests against PostgreSQL:

```bash
DB_PORT=55432 DB_NAME=maigo_test DB_USER=postgres DB_PASSWORD=password \
  docker compose -p maigo-audit up -d postgres
MAIGO_TEST_DATABASE_URL='postgres://postgres:password@localhost:55432/maigo_test?sslmode=disable' \
  mise exec -- go test ./tests/...
```

The test suite runs migrations and cleans its tables between tests. Stop the
isolated container when finished with:

```bash
docker compose -p maigo-audit stop postgres
```

Build and run the application with:

```bash
make build
./bin/maigo --help
```

## Configuration

Configuration is loaded in this order: the explicit `--config` path, the
`CONFIG_PATH` environment variable, the default config search paths, then
environment-variable overrides and command flags. For local development,
copy `.env.example` to `.env` and use `config/test.yaml` for the integration
database.

The server applies database migrations during startup. The CLI also exposes:

```bash
maigo migrate up
maigo migrate status
```

Use the pinned `migrate` binary for rollback; rollback is intentionally not an
application command because it is destructive:

```bash
mise exec -- migrate -path internal/database/migrations \
  -database "$DATABASE_URL" down 1
```

## API surface

The authoritative API reference is [`api/openapi.yaml`](api/openapi.yaml),
with usage notes in [`api/README.md`](api/README.md). The main routes are:

- `GET /health` and `GET /health/ready`
- `GET /metrics` for process-local Prometheus counters
- `GET /{code}` for public redirects
- `POST /api/v1/auth/register`, `/login`, `/refresh`, and `/logout`
- `POST /api/v1/urls`, `GET /api/v1/user/urls`, and
  `GET /api/v1/urls/{code}`
- `GET /api/v1/urls/{code}/stats` and `DELETE /api/v1/urls/{code}`
- `GET`/`POST /oauth/authorize`, `POST /oauth/token`, and `POST /oauth/revoke`

Protected endpoints require a verified `Authorization: Bearer <access-token>`
header. The CLI uses the public `maigo-cli` client and a random localhost
callback port; the server permits that narrow port variation only for the
registered localhost callback.

## Implementation boundaries

Keep the following limitations visible in code and documentation:

- statistics use persisted click events grouped into UTC day buckets;
- URL-create rate limiting is process-local and global;
- refresh sessions are stored per login/client, and JSON logout revokes all
  sessions for the authenticated user;
- expired refresh sessions are removed by the scheduled cleanup worker;
- access JWTs remain valid until expiry after logout;
- JWT signing uses a legacy single secret by default, with an optional HMAC
  key ring and active `kid` for rotation;
- click-event failures are logged and counted, but not retried through a durable
  outbox;
- metrics are process-local and reset on restart;
- click-event cleanup is configurable and disabled when retention is zero;
- default CORS and development secrets require hardening before deployment.

When changing behavior, update the OpenAPI document and integration coverage in
the same change. Prefer real PostgreSQL-backed tests for repository, auth,
OAuth, and expiration behavior; keep unit tests focused on pure validation and
helpers.
