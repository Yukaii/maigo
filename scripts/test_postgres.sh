#!/bin/bash

# Comprehensive PostgreSQL Integration Test Script
# This script sets up the database and runs all PostgreSQL tests

set -e  # Exit on any error

# Color output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

echo -e "${BLUE}=======================================${NC}"
echo -e "${BLUE}  Maigo PostgreSQL Integration Tests  ${NC}"
echo -e "${BLUE}=======================================${NC}"
echo

# Check if PostgreSQL is running
echo -n "Checking PostgreSQL status... "
if pg_isready -q; then
    echo -e "${GREEN}✓ running${NC}"
else
    echo -e "${RED}✗ not running${NC}"
    echo
    echo "Please start PostgreSQL first:"
    echo "  macOS (Homebrew): brew services start postgresql"
    echo "  Ubuntu/Debian: sudo systemctl start postgresql"
    echo "  Docker: docker run --name postgres -e POSTGRES_DB=maigo_test -p 5432:5432 -d postgres"
    exit 1
fi

# Setup test database
echo -e "\n${YELLOW}Setting up test database...${NC}"
./scripts/setup_postgres.sh test

# Build and run PostgreSQL integration tests
echo -e "\n${YELLOW}Building and running PostgreSQL integration tests...${NC}"
zig build test-postgres

echo -e "\n${GREEN}=======================================${NC}"
echo -e "${GREEN}  PostgreSQL Integration Tests PASSED  ${NC}"
echo -e "${GREEN}=======================================${NC}"
echo
echo "All PostgreSQL functionality is working correctly!"
echo
echo "You can now:"
echo "1. Use PostgreSQL for development: Update your app to use database_pg"
echo "2. Run individual tests: zig build test-postgres"
echo "3. Reset database: ./scripts/setup_postgres.sh reset"
echo "4. Clean database: ./scripts/setup_postgres.sh clean"