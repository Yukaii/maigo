#!/usr/bin/env bash
#
# Maigo Database Restore Script
# Restores PostgreSQL database from backup
#

set -euo pipefail

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

# Usage
usage() {
    cat <<EOF
Usage: $0 <backup_file>

Restore Maigo database from a backup file.

Arguments:
    backup_file    Path to the backup file (.sql or .sql.gz)

Environment Variables:
    DB_CONTAINER   Database container name (default: maigo-postgres)
    DB_USER        Database user (default: maigo)
    DB_NAME        Database name (default: maigo)

Examples:
    $0 backups/maigo_20250102_143000.sql.gz
    $0 /path/to/backup.sql
EOF
    exit 1
}

# Check arguments
if [ $# -ne 1 ]; then
    log_error "Missing backup file argument"
    usage
fi

BACKUP_FILE="$1"

# Validate backup file
if [ ! -f "$BACKUP_FILE" ]; then
    log_error "Backup file not found: $BACKUP_FILE"
    exit 1
fi

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

# Verify checksum if available
CHECKSUM_FILE="${BACKUP_FILE}.sha256"
if [ -f "$CHECKSUM_FILE" ]; then
    log_info "Verifying backup checksum..."
    if (cd "$(dirname "$BACKUP_FILE")" && sha256sum -c "$(basename "$CHECKSUM_FILE")" > /dev/null 2>&1); then
        log_info "Checksum verification passed"
    else
        log_error "Checksum verification failed!"
        read -p "Continue anyway? (yes/no): " -r
        if [[ ! $REPLY =~ ^[Yy][Ee][Ss]$ ]]; then
            exit 1
        fi
    fi
fi

# Warning
log_warn "WARNING: This will overwrite the current database!"
log_warn "Database: $DB_NAME on container $DB_CONTAINER"
log_warn "Backup file: $BACKUP_FILE"
echo ""
read -p "Are you sure you want to continue? Type 'yes' to confirm: " -r
echo ""

if [[ ! $REPLY =~ ^[Yy][Ee][Ss]$ ]]; then
    log_info "Restore cancelled"
    exit 0
fi

# Create a safety backup before restore
SAFETY_BACKUP="./backups/pre-restore_$(date +%Y%m%d_%H%M%S).sql.gz"
log_info "Creating safety backup before restore: $SAFETY_BACKUP"
mkdir -p ./backups
docker exec "$DB_CONTAINER" pg_dump -U "$DB_USER" "$DB_NAME" | gzip > "$SAFETY_BACKUP"
log_info "Safety backup created"

# Perform restore
log_info "Starting restore process..."

if [[ "$BACKUP_FILE" == *.gz ]]; then
    log_info "Detected gzipped backup file"
    if gunzip -c "$BACKUP_FILE" | docker exec -i "$DB_CONTAINER" psql -U "$DB_USER" "$DB_NAME"; then
        log_info "Restore completed successfully"
    else
        log_error "Restore failed!"
        log_warn "You can restore from the safety backup: $SAFETY_BACKUP"
        exit 1
    fi
else
    log_info "Detected SQL backup file"
    if docker exec -i "$DB_CONTAINER" psql -U "$DB_USER" "$DB_NAME" < "$BACKUP_FILE"; then
        log_info "Restore completed successfully"
    else
        log_error "Restore failed!"
        log_warn "You can restore from the safety backup: $SAFETY_BACKUP"
        exit 1
    fi
fi

# Verify restore
log_info "Verifying database connection..."
if docker exec "$DB_CONTAINER" psql -U "$DB_USER" "$DB_NAME" -c "SELECT COUNT(*) FROM urls;" > /dev/null 2>&1; then
    log_info "Database verification passed"
else
    log_warn "Database verification failed - tables may not exist yet"
fi

log_info "Restore completed successfully!"
log_info "Safety backup is available at: $SAFETY_BACKUP"
