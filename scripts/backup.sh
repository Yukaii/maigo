#!/usr/bin/env bash

# Back up the SQLite file from the Compose data volume. The service is stopped
# briefly so the database, WAL, and shared-memory files are consistent.
set -euo pipefail

BACKUP_DIR="${BACKUP_DIR:-./backups}"
CONTAINER="${MAIGO_CONTAINER:-maigo-app}"
COMPOSE_FILE="${COMPOSE_FILE:-docker-compose.yml}"
DATE="$(date -u +%Y%m%d_%H%M%S)"
BACKUP_FILE="maigo_${DATE}.tar.gz"

mkdir -p "$BACKUP_DIR"
BACKUP_DIR_ABS="$(cd "$BACKUP_DIR" && pwd)"

if ! docker inspect "$CONTAINER" >/dev/null 2>&1; then
	printf 'Container not found: %s\n' "$CONTAINER" >&2
	exit 1
fi

restart=0
if [ "$(docker inspect -f '{{.State.Running}}' "$CONTAINER")" = "true" ]; then
	docker compose -f "$COMPOSE_FILE" stop maigo
	restart=1
fi
restore_service() {
	if [ "$restart" -eq 1 ]; then
		docker compose -f "$COMPOSE_FILE" start maigo >/dev/null
	fi
}
trap restore_service EXIT

docker run --rm --volumes-from "$CONTAINER" -v "$BACKUP_DIR_ABS:/backup" alpine:3.22 \
	tar -czf "/backup/$BACKUP_FILE" -C /data maigo.db

(cd "$BACKUP_DIR_ABS" && sha256sum "$BACKUP_FILE" > "$BACKUP_FILE.sha256")
printf 'Created %s/%s\n' "$BACKUP_DIR" "$BACKUP_FILE"
