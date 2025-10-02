#!/usr/bin/env bash
#
# Maigo Database Backup Script
# Backs up PostgreSQL database with rotation and compression
#

set -euo pipefail

# Configuration
BACKUP_DIR="${BACKUP_DIR:-./backups}"
RETENTION_DAYS="${RETENTION_DAYS:-30}"
DATE=$(date +%Y%m%d_%H%M%S)
BACKUP_FILE="maigo_${DATE}.sql.gz"

# Docker configuration
COMPOSE_FILE="${COMPOSE_FILE:-docker-compose.yml}"
DB_CONTAINER="${DB_CONTAINER:-maigo-postgres}"
DB_USER="${DB_USER:-maigo}"
DB_NAME="${DB_NAME:-maigo}"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Logging functions
log_info() {
    echo -e "${GREEN}[INFO]${NC} $1"
}

log_warn() {
    echo -e "${YELLOW}[WARN]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Create backup directory if it doesn't exist
mkdir -p "$BACKUP_DIR"

# Check if Docker is running
if ! docker ps > /dev/null 2>&1; then
    log_error "Docker is not running or you don't have permission to access it"
    exit 1
fi

# Check if database container is running
if ! docker ps --format '{{.Names}}' | grep -q "^${DB_CONTAINER}$"; then
    log_error "Database container '$DB_CONTAINER' is not running"
    exit 1
fi

log_info "Starting backup process..."
log_info "Backup directory: $BACKUP_DIR"
log_info "Database: $DB_NAME"

# Perform backup
log_info "Creating backup: $BACKUP_FILE"
if docker exec "$DB_CONTAINER" pg_dump -U "$DB_USER" "$DB_NAME" | gzip > "$BACKUP_DIR/$BACKUP_FILE"; then
    log_info "Backup created successfully"

    # Get file size
    SIZE=$(du -h "$BACKUP_DIR/$BACKUP_FILE" | cut -f1)
    log_info "Backup size: $SIZE"
else
    log_error "Backup failed"
    exit 1
fi

# Create checksum
log_info "Creating checksum..."
(cd "$BACKUP_DIR" && sha256sum "$BACKUP_FILE" > "${BACKUP_FILE}.sha256")

# Cleanup old backups
log_info "Cleaning up backups older than $RETENTION_DAYS days..."
DELETED_COUNT=$(find "$BACKUP_DIR" -name "maigo_*.sql.gz" -type f -mtime +$RETENTION_DAYS -delete -print | wc -l)
find "$BACKUP_DIR" -name "maigo_*.sql.gz.sha256" -type f -mtime +$RETENTION_DAYS -delete

if [ "$DELETED_COUNT" -gt 0 ]; then
    log_info "Deleted $DELETED_COUNT old backup(s)"
else
    log_info "No old backups to delete"
fi

# List recent backups
log_info "Recent backups:"
ls -lh "$BACKUP_DIR"/maigo_*.sql.gz | tail -5

log_info "Backup completed successfully: $BACKUP_FILE"
