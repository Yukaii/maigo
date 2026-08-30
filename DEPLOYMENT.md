# Maigo deployment guide

Maigo is a working prototype. The image and Compose setup are useful for a
production-like evaluation, but review the status document before exposing it
to untrusted traffic. In particular, use HTTPS, real secret management, and a
distributed edge rate limiter.

## Prerequisites

- Docker 20.10+ and Docker Compose v2
- PostgreSQL 15+ (the included Compose service uses PostgreSQL 16)
- At least 1 GB RAM for the local stack

## Compose deployment

The tracked docker-compose.yml builds Dockerfile.production, starts PostgreSQL,
and waits for the database health check before starting Maigo. Migrations run
automatically when the application starts.

~~~bash
cp .env.production.example .env.production
# Edit .env.production: set a real DB_PASSWORD and JWT_SECRET at minimum.

docker compose --env-file .env.production config --quiet
docker compose --env-file .env.production up -d --build
docker compose --env-file .env.production ps
curl http://localhost:8080/health
curl http://localhost:8080/health/ready
~~~

BASE_DOMAIN should be the public hostname without a trailing slash. Set
APP_TLS=true only when the public endpoint is HTTPS (usually behind a reverse
proxy); leave it false for a direct local HTTP deployment. The Compose Redis
profile is not required and is not connected to the current server; the active
URL-create limiter is process-local.

Stop the services while retaining database volumes:

~~~bash
docker compose --env-file .env.production stop
~~~

docker compose down removes containers and networks. docker compose down -v
also removes the PostgreSQL volume and is destructive.

## Building the image directly

~~~bash
docker build -f Dockerfile.production -t maigo:local .
docker image inspect maigo:local --format '{{.Size}} bytes'
~~~

The production image runs as the non-root maigo user and includes the tracked
maigo.example.yaml template. Runtime settings should come from environment
variables or an explicitly mounted config file.

## Configuration

The application accepts either DATABASE_URL or the individual DB_* variables.
Compose passes individual database variables so passwords containing URL
punctuation are not accidentally mis-parsed. Common deployment settings:

~~~bash
DB_HOST=postgres
DB_PORT=5432
DB_NAME=maigo
DB_USER=maigo
DB_PASSWORD=<strong-password>
DB_SSL_MODE=disable       # use require with a TLS-enabled external database

PORT=8080
HOST=0.0.0.0
BASE_DOMAIN=short.example.com
APP_TLS=true              # only when HTTPS is provided at the public edge
JWT_SECRET=<long-random-secret>
JWT_EXPIRATION=24h
CORS_ENABLED=false
DEBUG=false
LOG_LEVEL=info
LOG_FORMAT=json
~~~

OAUTH2_CLIENT_ID, OAUTH2_CLIENT_SECRET, and OAUTH2_REDIRECT_URI describe the
bundled CLI client. The CLI uses PKCE and a localhost callback; this is not yet
a general-purpose multi-client authorization service.

Configuration precedence and all supported variables are documented in the
README and maigo.example.yaml.

## Migrations

Migrations are applied automatically during server startup. They can also be
applied from a running Compose service:

~~~bash
docker compose --env-file .env.production exec maigo /usr/local/bin/maigo migrate up
docker compose --env-file .env.production exec maigo /usr/local/bin/maigo migrate status
~~~

Take a backup before a rollback. The application intentionally does not expose
a destructive migrate down command; use the pinned migrate tool with a
reachable database URL:

~~~bash
mise install
mise exec -- migrate -path internal/database/migrations \
  -database "$DATABASE_URL" down 1
~~~

## Backups and restore

The scripts use the fixed Compose database container name maigo-postgres.
Export the production values before invoking them:

~~~bash
set -a
. ./.env.production
set +a

./scripts/backup.sh
./scripts/restore.sh backups/maigo_<timestamp>.sql.gz
~~~

backup.sh compresses the dump, writes a SHA-256 sidecar, and rotates files
older than RETENTION_DAYS (30 by default). restore.sh verifies a sidecar when
present, asks for confirmation, and creates a safety backup first. Test
restores separately; a backup that has never been restored is not a recovery
plan.

For an external database, use pg_dump/pg_restore with the database provider's
credentials and set DATABASE_URL for the application.

## Reverse proxy

Terminate TLS at nginx, Caddy, or a managed load balancer and proxy to the HTTP
service on port 8080. Forward the original host and scheme:

~~~nginx
server {
    listen 443 ssl;
    server_name short.example.com;

    ssl_certificate /etc/letsencrypt/live/short.example.com/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/short.example.com/privkey.pem;

    location / {
        proxy_pass http://127.0.0.1:8080;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }
}
~~~

The application does not provision certificates or implement proxy trust
configuration itself. Keep the app port private when a reverse proxy is in
front of it.

## Operations

Useful checks:

~~~bash
docker compose --env-file .env.production logs -f maigo
docker compose --env-file .env.production logs --tail=100 postgres
docker compose --env-file .env.production exec maigo /usr/local/bin/maigo version
docker compose --env-file .env.production exec postgres \
  psql -U "$DB_USER" -d "$DB_NAME" -c 'SELECT 1'
~~~

The /health endpoint is liveness-only; /health/ready also checks the database.
Monitor both, plus container restarts, database disk usage, backup success, and
5xx rates.

Do not horizontally scale the service without replacing the process-local
limiter and deciding how refresh sessions should work across devices. The
current schema intentionally permits one active refresh session per user.

## Pre-exposure checklist

- [ ] Replace all example database and JWT secrets.
- [ ] Set BASE_DOMAIN and APP_TLS for the public endpoint.
- [ ] Put the service behind HTTPS and an edge/API rate limiter.
- [ ] Set CORS_ENABLED=false unless a specific browser origin is needed.
- [ ] Restrict the application port and database port at the network layer.
- [ ] Configure automated backups and perform a restore drill.
- [ ] Configure log collection and alerting for readiness failures.
- [ ] Read docs/STATUS.md and accept its limitations.
