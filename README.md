# Maigo Core

Maigo Core is a small self-hosted URL shortener for one owner or one trusted
installation. It keeps the useful parts of the original toy project—short
links, aliases, expiry, hit counts, a CLI, and automation access—without
requiring accounts, OAuth, Postgres, or Redis.

Core has one API key, one SQLite file, and one application container. See
[`docs/CORE.md`](docs/CORE.md) for the intentional product boundary and
[`docs/STATUS.md`](docs/STATUS.md) for the current verification status.

## Quick start with Docker

```bash
cp .env.production.example .env.production
openssl rand -hex 32
# Put the generated value in API_KEY and set PUBLIC_URL.
docker compose --env-file .env.production up -d --build
curl http://127.0.0.1:8080/health/ready
```

For a local-only development server:

```bash
cp .env.example .env
set -a; . ./.env; set +a
mise install
mise exec -- go run ./cmd/maigo server
```

The default database is `data/maigo.db`. It is created and initialized on
startup; no migration command or external service is needed.

## CLI

The CLI uses the same `PUBLIC_URL` and `API_KEY` as the server. It never opens
a browser or writes a token file.

```bash
maigo shorten https://example.com --custom docs --ttl 86400
maigo list
maigo get docs
maigo stats docs
maigo delete docs --force
```

Use `--server URL` and `--api-key KEY` to override configuration for one
command. Add `--json` to `shorten`, `list`, `get`, `stats`, or `delete` for
script-friendly output. Configuration can also be supplied with
`--config path/to/maigo.yaml` or environment variables.

## MCP

Run the local MCP server over stdio:

```bash
maigo mcp
```

Example client configuration:

```json
{
  "mcpServers": {
    "maigo": {
      "command": "/usr/local/bin/maigo",
      "args": ["mcp"],
      "env": {
        "PUBLIC_URL": "https://short.example.com",
        "API_KEY": "replace-with-your-api-key"
      }
    }
  }
}
```

The server exposes `shorten_url`, `list_urls`, `get_url`, `get_url_stats`, and
`delete_url`. It talks to the Maigo HTTP API, so the MCP process needs network
access to the configured `PUBLIC_URL`.

## HTTP API

Management requests accept either `Authorization: Bearer <API_KEY>` or
`X-Maigo-API-Key: <API_KEY>`.

```bash
curl -X POST https://short.example.com/api/v1/urls \
  -H "Authorization: Bearer $API_KEY" \
  -H 'Content-Type: application/json' \
  -d '{"url":"https://example.com/docs","custom":"docs","ttl":86400}'

curl https://short.example.com/docs
curl -H "Authorization: Bearer $API_KEY" \
  https://short.example.com/api/v1/urls/docs/stats
```

See [`api/README.md`](api/README.md) and [`api/openapi.yaml`](api/openapi.yaml)
for the complete contract.

## DNS and TLS

Point one A/AAAA or CNAME record at the host running the container. Put Caddy,
Traefik, Cloudflare, Tailscale, or another ordinary edge proxy in front of
port 8080 to terminate TLS, and set `PUBLIC_URL` to the resulting HTTPS URL.
Maigo does not provision DNS records or certificates and is intentionally a
single-instance service.

## Development

```bash
make setup
make test       # race-enabled unit and SQLite integration tests
make build
make lint
make check-goreleaser
```

The pinned toolchain is in [`mise.toml`](mise.toml). Tests do not require
Postgres, Redis, a browser, or network access.

## Project layout

```text
cmd/maigo/                 CLI entry point
internal/cli/              HTTP client and CLI commands
internal/config/           configuration loading and validation
internal/database/         SQLite schema, repository, and models
internal/mcpserver/        local stdio MCP tools
internal/server/           HTTP routes, handlers, and middleware
internal/shortener/        Base62 and URL validation logic
tests/                     SQLite-backed HTTP integration tests
api/                       OpenAPI specification and API notes
docs/CORE.md               product boundary and stopping point
```

## License

MIT License — see [`LICENSE`](LICENSE).
