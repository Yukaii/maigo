#!/usr/bin/env bash

# Restore a SQLite backup created by scripts/backup.sh.
set -euo pipefail

if [ "$#" -ne 1 ]; then
	printf 'Usage: %s backups/maigo_YYYYMMDD_HHMMSS.tar.gz\n' "$0" >&2
	exit 1
fi

BACKUP_FILE="$1"
CONTAINER="${MAIGO_CONTAINER:-maigo-app}"
COMPOSE_FILE="${COMPOSE_FILE:-docker-compose.yml}"
if [ ! -f "$BACKUP_FILE" ]; then
	printf 'Backup not found: %s\n' "$BACKUP_FILE" >&2
	exit 1
fi

CHECKSUM_FILE="$BACKUP_FILE.sha256"
if [ -f "$CHECKSUM_FILE" ] && ! (cd "$(dirname "$BACKUP_FILE")" && sha256sum -c "$(basename "$CHECKSUM_FILE")"); then
	printf 'Backup checksum failed\n' >&2
	exit 1
fi

printf 'This replaces the current SQLite database. Type yes to continue: '
read -r confirmation
if [ "$confirmation" != "yes" ]; then
	printf 'Restore canceled.\n'
	exit 0
fi

if ! docker inspect "$CONTAINER" >/dev/null 2>&1; then
	printf 'Container not found: %s\n' "$CONTAINER" >&2
	exit 1
fi

restart=0
if [ "$(docker inspect -f '{{.State.Running}}' "$CONTAINER")" = "true" ]; then
	docker compose -f "$COMPOSE_FILE" stop maigo
	restart=1
fi
start_service() {
	if [ "$restart" -eq 1 ]; then
		docker compose -f "$COMPOSE_FILE" start maigo >/dev/null
	fi
}
trap start_service EXIT

BACKUP_DIR_ABS="$(cd "$(dirname "$BACKUP_FILE")" && pwd)"
BACKUP_BASENAME="$(basename "$BACKUP_FILE")"
PRE_RESTORE_FILE="maigo_pre_restore_$(date -u +%Y%m%d_%H%M%S).tar.gz"
docker run --rm --volumes-from "$CONTAINER" -v "$BACKUP_DIR_ABS:/backup" alpine:3.22 \
	sh -c '
set -eu
backup="$1"
safety="$2"
[ "$(tar -tzf "/backup/$backup")" = "maigo.db" ]
rm -rf /data/.maigo-restore
mkdir /data/.maigo-restore
tar -xzf "/backup/$backup" -C /data/.maigo-restore maigo.db
test -f /data/.maigo-restore/maigo.db
if [ -f /data/maigo.db ]; then
	tar -czf "/backup/$safety" -C /data maigo.db
fi
rm -f /data/maigo.db /data/maigo.db-wal /data/maigo.db-shm
mv /data/.maigo-restore/maigo.db /data/maigo.db
rm -rf /data/.maigo-restore
' -- "$BACKUP_BASENAME" "$PRE_RESTORE_FILE"
if [ -f "$BACKUP_DIR_ABS/$PRE_RESTORE_FILE" ]; then
	(cd "$BACKUP_DIR_ABS" && sha256sum "$PRE_RESTORE_FILE" > "$PRE_RESTORE_FILE.sha256")
	printf 'Safety backup: %s/%s\n' "$(dirname "$BACKUP_FILE")" "$PRE_RESTORE_FILE"
fi
printf 'Restored %s\n' "$BACKUP_FILE"
