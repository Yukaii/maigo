# Maigo Core deployment

Maigo Core is intentionally a single-instance self-hosted service. The
production topology is one container, one persistent SQLite volume, and one
ordinary TLS reverse proxy at the edge.

## Prerequisites

- Docker 20.10+ and Docker Compose v2
- One host with a persistent disk for the SQLite volume
- One DNS A/AAAA or CNAME record pointing at the host
- Caddy, Traefik, Cloudflare, Tailscale, or another TLS reverse proxy

Postgres, Redis, a browser, and a separate migration service are not required.

## Compose deployment

```bash
cp .env.production.example .env.production
openssl rand -hex 32
# Put the generated value in API_KEY and set PUBLIC_URL, for example:
# PUBLIC_URL=https://short.example.com

docker compose --env-file .env.production config --quiet
docker compose --env-file .env.production up -d --build
docker compose --env-file .env.production ps
curl https://short.example.com/health/ready
```

The Compose service listens on port 8080 inside the container and persists
`/data/maigo.db` in the named `maigo_data` volume. Set `PORT` to change the
host-side port mapping. `APP_ENV=production` rejects debug mode and short or
placeholder API keys.

Stop the service without removing its data:

```bash
docker compose --env-file .env.production stop
```

`docker compose down` removes the container. Do not use `down -v` unless the
SQLite volume has been backed up and you intend to remove it.

## DNS and TLS

Create one record such as:

```text
short.example.com  A      <host-ip>
```

Terminate TLS at the edge and reverse proxy to `127.0.0.1:8080`. A minimal
Caddyfile is:

```text
short.example.com {
    reverse_proxy 127.0.0.1:8080
}
```

Set `PUBLIC_URL=https://short.example.com` so generated links are canonical.
Maigo does not create DNS records, request certificates, or manage proxy
configuration.

## Configuration

The essential settings are:

| Variable | Purpose |
| --- | --- |
| `DATABASE_PATH` | SQLite file path; Compose uses `/data/maigo.db` |
| `API_KEY` | The single management credential |
| `PUBLIC_URL` | Canonical origin used in generated links |
| `HOST` / `PORT` | Listener address; Compose uses `0.0.0.0:8080` |
| `APP_ENV` | Use `production` for fail-fast secret checks |
| `SHORT_CODE_LENGTH` | Random code length, from 3 to 10 |
| `LOG_LEVEL` / `LOG_FORMAT` | Application logging settings |

Configuration can also be supplied in `maigo.yaml`; environment variables take
precedence. See [`maigo.example.yaml`](maigo.example.yaml) and
[`api/README.md`](api/README.md).

## Backups and restore

The database is a single SQLite file. The repository includes scripts that
briefly stop the Compose service, create a compressed archive, and write a
SHA-256 checksum:

```bash
./scripts/backup.sh
./scripts/restore.sh backups/maigo_YYYYMMDD_HHMMSS.tar.gz
```

Restore creates a timestamped `maigo_pre_restore_*.tar.gz` safety backup before
replacing the current database. Keep at least one backup off the host and
perform a restore drill before relying on the service.

## Operations

```bash
docker compose --env-file .env.production logs -f maigo
docker compose --env-file .env.production exec maigo /usr/local/bin/maigo version
curl https://short.example.com/health
curl https://short.example.com/health/ready
```

`/health` is process liveness. `/health/ready` also checks SQLite. Management
requests use the API key; redirects and metadata are public. Put any request
rate limiting, WAF policy, access logging, and abuse controls at the edge.

## MCP deployment

Run `maigo mcp` wherever the MCP host can reach `PUBLIC_URL`, and provide the
same `API_KEY` in that process environment. The MCP server uses stdio and
does not open a network listener of its own.

## Deliberate limits

Core is not a horizontally scaled or multi-tenant service. It has no OAuth,
user accounts, session store, Redis dependency, distributed limiter,
click-event timeline, app-managed domains, or app-managed TLS. Those are
separate product decisions, not hidden deployment prerequisites.
