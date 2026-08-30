# Maigo Core contributor guide

Maigo Core is a small self-hosted URL shortener written in Go. It is a
single-owner service with a SQLite file, one API key, a CLI, and a local stdio
MCP server.

Read [`docs/CORE.md`](docs/CORE.md) for the product boundary and
[`docs/STATUS.md`](docs/STATUS.md) for verification and known limits.

## Stack and layout

- Go 1.25.14 managed locally with mise
- Gin HTTP server and Cobra CLI
- SQLite via `database/sql` and the pure-Go modernc driver
- Official Go MCP SDK for the local stdio server
- `cmd/maigo`: executable entry point
- `internal/cli`: API client and user-facing commands
- `internal/config`: configuration loading and validation
- `internal/database`: schema bootstrap, repository, and models
- `internal/mcpserver`: MCP tool registration and output mapping
- `internal/server`: HTTP routes, handlers, and middleware
- `internal/shortener`: Base62 code and URL validation
- `tests/integration_test.go`: SQLite-backed HTTP integration suite

## Local workflow

```bash
make setup
make fmt-check
make lint
make test
make build
```

The tests use temporary SQLite files and must not require Postgres, Redis, a
browser, network access, or an externally running service.

## Configuration

`maigo.yaml` can provide configuration, and environment variables override it.
The important variables are `DATABASE_PATH`, `API_KEY`, `PUBLIC_URL`, `HOST`,
`PORT`, `APP_ENV`, `SHORT_CODE_LENGTH`, `DEBUG`, `LOG_LEVEL`, and `LOG_FORMAT`.

The server initializes the current SQLite schema during startup. There is no
`migrate` command. Management routes require the API key as either a bearer
token or `X-Maigo-API-Key`.

## API and MCP

The authoritative HTTP contract is [`api/openapi.yaml`](api/openapi.yaml), with
examples in [`api/README.md`](api/README.md). The public routes are health,
short-code metadata, and redirects; create/list/stats/delete are protected
management operations.

`maigo mcp` speaks MCP over stdin/stdout and calls the configured HTTP API. Do
not write logs or diagnostics to stdout in that mode; stdout is the JSON-RPC
transport.

## Implementation boundaries

Keep Core narrow: one owner, one API key, one SQLite database, one instance,
lifetime hit counts, and five MCP tools. DNS, TLS, WAF/rate limiting, abuse
controls, and backups belong to deployment tooling or the operator.

OAuth, accounts, JWTs, sessions, Redis, distributed rate limiting,
click-event timelines, multi-tenant ownership, application-managed domains,
and application-managed certificates are explicitly deferred. If a change
needs one of those capabilities, update `docs/CORE.md` and the status document
as a product decision before implementing it.

When changing behavior, update the OpenAPI document, CLI help, documentation,
and integration coverage together.
