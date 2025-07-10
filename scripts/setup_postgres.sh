#!/bin/bash

# PostgreSQL Database Setup Script for Maigo URL Shortener
# This script sets up local development and test databases

set -e  # Exit on any error

# Color output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

echo -e "${GREEN}Setting up PostgreSQL databases for Maigo...${NC}"

# Check if PostgreSQL is running
if ! pg_isready -q; then
    echo -e "${RED}Error: PostgreSQL is not running${NC}"
    echo "Please start PostgreSQL first:"
    echo "  macOS (Homebrew): brew services start postgresql"
    echo "  Ubuntu/Debian: sudo systemctl start postgresql"
    echo "  Docker: docker run --name postgres -e POSTGRES_PASSWORD=password -p 5432:5432 -d postgres"
    exit 1
fi

echo -e "${GREEN}✓ PostgreSQL is running${NC}"

# Database configuration
DB_USER=${POSTGRES_USER:-$USER}
DB_HOST=${POSTGRES_HOST:-localhost}
DB_PORT=${POSTGRES_PORT:-5432}

# Development database
DEV_DB=${POSTGRES_DB:-maigo_dev}
# Test database  
TEST_DB=${POSTGRES_TEST_DB:-maigo_test}

echo "Using connection parameters:"
echo "  Host: $DB_HOST"
echo "  Port: $DB_PORT"
echo "  User: $DB_USER"
echo "  Dev Database: $DEV_DB"
echo "  Test Database: $TEST_DB"
echo

# Function to create database if it doesn't exist
create_database() {
    local db_name=$1
    echo -n "Creating database '$db_name'... "
    
    if psql -h "$DB_HOST" -p "$DB_PORT" -U "$DB_USER" -lqt | cut -d \| -f 1 | grep -qw "$db_name"; then
        echo -e "${YELLOW}already exists${NC}"
    else
        createdb -h "$DB_HOST" -p "$DB_PORT" -U "$DB_USER" "$db_name"
        echo -e "${GREEN}created${NC}"
    fi
}

# Function to drop database if it exists
drop_database() {
    local db_name=$1
    echo -n "Dropping database '$db_name'... "
    
    if psql -h "$DB_HOST" -p "$DB_PORT" -U "$DB_USER" -lqt | cut -d \| -f 1 | grep -qw "$db_name"; then
        dropdb -h "$DB_HOST" -p "$DB_PORT" -U "$DB_USER" "$db_name"
        echo -e "${GREEN}dropped${NC}"
    else
        echo -e "${YELLOW}does not exist${NC}"
    fi
}

# Parse command line arguments
case "${1:-setup}" in
    "setup")
        echo "Setting up development and test databases..."
        create_database "$DEV_DB"
        create_database "$TEST_DB"
        echo -e "${GREEN}✓ Database setup complete${NC}"
        ;;
    "reset")
        echo "Resetting databases (dropping and recreating)..."
        drop_database "$DEV_DB"
        drop_database "$TEST_DB"
        create_database "$DEV_DB"
        create_database "$TEST_DB"
        echo -e "${GREEN}✓ Database reset complete${NC}"
        ;;
    "clean")
        echo "Cleaning up databases..."
        drop_database "$DEV_DB"
        drop_database "$TEST_DB"
        echo -e "${GREEN}✓ Database cleanup complete${NC}"
        ;;
    "test")
        echo "Setting up test database only..."
        create_database "$TEST_DB"
        echo -e "${GREEN}✓ Test database setup complete${NC}"
        ;;
    *)
        echo "Usage: $0 [setup|reset|clean|test]"
        echo "  setup  - Create development and test databases (default)"
        echo "  reset  - Drop and recreate databases"
        echo "  clean  - Drop databases"
        echo "  test   - Create test database only"
        exit 1
        ;;
esac

echo
echo "Next steps:"
echo "1. Run integration tests: zig build test-postgres"
echo "2. Start development server with PostgreSQL"
echo
echo "Connection examples:"
echo "  psql $DEV_DB"
echo "  psql $TEST_DB"
echo
echo "Environment variables for custom configuration:"
echo "  POSTGRES_HOST=localhost"
echo "  POSTGRES_PORT=5432"  
echo "  POSTGRES_USER=$USER"
echo "  POSTGRES_DB=maigo_dev"
echo "  POSTGRES_TEST_DB=maigo_test"