# Maigo

Maigo is a small, terminal-first URL shortener written in Go. It has a Gin
HTTP API, a Cobra CLI, PostgreSQL persistence, OAuth 2.0 authorization-code
flow with PKCE, and a minimal browser consent screen.

This is a polished prototype rather than a finished hosted service. The
current implementation and verification status are tracked in
[`docs/STATUS.md`](docs/STATUS.md).

## Quick start

Install the pinned development tools and run the unit suite:

```bash
make setup
make test-unit
```

For a local database, start PostgreSQL with Compose, load the environment
template into the shell, and start the server:

```bash
cp .env.example .env
docker compose up -d postgres
set -a; . ./.env; set +a
mise exec -- go run ./cmd/maigo server
```

The server runs on `http://127.0.0.1:8080` by default and applies embedded
database migrations on startup. The default Compose database is suitable for
local development only. Change `JWT_SECRET` and database credentials before
using the service anywhere shared.

## CLI

```bash
maigo auth register <username> <email>
maigo auth login <username>       # opens the browser-based PKCE flow
maigo auth status
maigo auth logout

maigo shorten <url>
maigo shorten <url> --custom <code> --ttl 86400
maigo list --page 1 --page-size 20
maigo get <short-code>
maigo stats <short-code>
maigo delete <short-code> --force
```

The CLI stores its local token file under the platform-specific user config
directory. `--config path/to/maigo.yaml` and `CONFIG_PATH` select a config
file; environment variables override file values, and command-line flags
override both.

Development tools are pinned in [`mise.toml`](mise.toml): Go, Air,
golangci-lint, migrate, GoReleaser, and goimports.

`APP_ENV=production` enables fail-fast checks for deployment-safe secrets and
debug settings. CORS origins are configured with the comma-separated
`CORS_ORIGINS` variable. Set `REDIS_ENABLED=true` to use the atomic distributed
rate limiter; when Redis is disabled, the server uses a bounded per-client
in-process limiter. Forwarded client-IP headers are ignored unless their proxy
network is listed in `TRUSTED_PROXIES`.

## HTTP API

Health:

- `GET /health` — liveness check.
- `GET /health/ready` — liveness plus database connectivity.

Authentication:

- `POST /api/v1/auth/register` — create an account and return tokens.
- `POST /api/v1/auth/login` — log in with username or email.
- `POST /api/v1/auth/token` — JSON refresh-token compatibility endpoint.
- `POST /api/v1/auth/logout` — revoke the authenticated user’s refresh session.
- `GET|POST /oauth/authorize` — browser authorization and consent.
- `POST /oauth/token` — OAuth authorization-code or refresh-token exchange.
- `POST /oauth/revoke` — revoke a refresh token.

URL management:

- `POST /api/v1/urls` — create a URL; authentication required.
- `GET /api/v1/user/urls` — list the authenticated user’s URLs.
- `GET /api/v1/urls/{code}` — read public URL metadata.
- `GET /api/v1/urls/{code}/stats` — read owned URL statistics.
- `DELETE /api/v1/urls/{code}` — delete an owned URL.
- `GET /{code}` — redirect to the target and count a hit.

See [`api/README.md`](api/README.md) and [`api/openapi.yaml`](api/openapi.yaml)
for request and response examples.

## Development commands

```bash
make test-unit          # unit tests with race detection
make test-integration   # resets the configured test DB, then runs integration tests
make test               # unit + integration
make build              # build bin/maigo
make lint
make fmt-check
make check-goreleaser
```

The integration suite needs PostgreSQL. For an isolated local database:

```bash
DB_PORT=55432 DB_NAME=maigo_test DB_USER=postgres DB_PASSWORD=password \
  docker compose -p maigo-audit up -d postgres
MAIGO_TEST_DATABASE_URL='postgres://postgres:password@localhost:55432/maigo_test?sslmode=disable' \
  mise exec -- go test ./tests/...
```

`make test-unit` is the database-free check. `make test-integration` uses
`scripts/setup_test_db.sh`, which intentionally drops and recreates the
configured test database.

## Project layout

```text
cmd/maigo/                 CLI entry point
internal/cli/              CLI commands and OAuth client
internal/config/           configuration loading and validation
internal/database/         PostgreSQL connection, migrations, repositories
internal/oauth/            PKCE, authorization codes, JWT/session handling
internal/server/           HTTP routes, handlers, middleware, templates
internal/shortener/        Base62 and URL validation logic
tests/                     PostgreSQL-backed integration tests
api/                       OpenAPI specification and API notes
maigo.example.yaml         tracked YAML configuration template
mise.toml                  pinned local toolchain
```

## License

MIT License — see [`LICENSE`](LICENSE).
