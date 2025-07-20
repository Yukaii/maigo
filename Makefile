.PHONY: help setup build test test-unit test-integration test-setup test-clean lint fmt clean dev server migrate-up migrate-down db-setup db-reset db-seed
.DEFAULT_GOAL := help

# Variables
GO_VERSION := 1.21
BINARY_NAME := maigo
MAIN_PACKAGE := ./cmd/$(BINARY_NAME)
COVERAGE_FILE := coverage.out

# Build info
BUILD_TIME := $(shell date -u +"%Y-%m-%dT%H:%M:%SZ")
GIT_COMMIT := $(shell git rev-parse --short HEAD 2>/dev/null || echo "unknown")
VERSION := $(shell git describe --tags --always --dirty 2>/dev/null || echo "dev")

# LDFLAGS for version info
LDFLAGS := -ldflags "-X main.Version=$(VERSION) -X main.BuildTime=$(BUILD_TIME) -X main.GitCommit=$(GIT_COMMIT)"

## help: Show this help message
help:
	@echo "Available commands:"
	@sed -n 's/^##//p' $(MAKEFILE_LIST) | column -t -s ':' | sed -e 's/^/ /'

## setup: Initialize development environment
setup:
	@echo "Setting up development environment..."
	go version
	go mod download
	go mod tidy
	@if [ ! -f .env ]; then cp .env.example .env; else echo ".env already exists, skipping copy."; fi
	@echo "Installing development tools..."
	go install github.com/air-verse/air@latest
	go install github.com/golangci/golangci-lint/cmd/golangci-lint@latest
	go install github.com/golang-migrate/migrate/v4/cmd/migrate@latest
	go install golang.org/x/tools/cmd/goimports@latest
	go install github.com/goreleaser/goreleaser/v2@latest
	@echo "Setup complete! Edit .env file with your configuration."

## build: Build the binary
build: clean
	@echo "Building binary..."
	CGO_ENABLED=0 go build $(LDFLAGS) -o bin/$(BINARY_NAME) $(MAIN_PACKAGE)
	@echo "Built: bin/$(BINARY_NAME)"

## dev: Start development server with hot reload
dev:
	@echo "Starting development server with hot reload..."
	air

## test: Run all tests
test: test-unit test-integration

## test-unit: Run unit tests only
test-unit:
	@echo "Running unit tests..."
	go test -v -race -short ./internal/...

## test-integration: Run integration tests
test-integration: test-setup
	@echo "Running integration tests..."
	CONFIG_PATH=config/test.yaml go test -v ./tests/...

## test-setup: Set up test database
test-setup:
	@echo "Setting up test database..."
	./scripts/setup_test_db.sh

## test-clean: Clean up test database
test-clean:
	@echo "Cleaning up test database..."
	PGPASSWORD=password psql -h localhost -p 5432 -U postgres -d postgres -c "DROP DATABASE IF EXISTS maigo_test;" || true

## coverage: Generate test coverage report
coverage:
	@echo "Generating coverage report..."
	go test -v -race -coverprofile=$(COVERAGE_FILE) ./...
	go tool cover -html=$(COVERAGE_FILE) -o coverage.html
	@echo "Coverage report generated: coverage.html"

## benchmark: Run benchmarks
benchmark:
	@echo "Running benchmarks..."
	go test -bench=. -benchmem ./...

## lint: Run linter
lint:
	@echo "Running linter..."
	golangci-lint run

## lint-full: Run full linter with config
lint-full:
	@echo "Running full linter..."
	golangci-lint run

## lint-fix: Run linter with auto-fix
lint-fix:
	@echo "Running linter with auto-fix..."
	golangci-lint run --no-config --disable-all -E errcheck -E gosimple -E govet -E ineffassign -E unused -E gofmt -E goimports -E misspell --fix ./...

## fmt: Format code
fmt:
	@echo "Formatting code..."
	gofmt -s -w .
	goimports -w .
	go mod tidy

## fmt-check: Check if code is formatted
fmt-check:
	@echo "Checking code formatting..."
	@if [ "$$(gofmt -s -l . | wc -l)" -gt 0 ]; then \
		echo "Code is not formatted. Run 'make fmt' to fix."; \
		gofmt -s -l .; \
		exit 1; \
	fi
	@echo "Code is properly formatted."

## clean: Clean build artifacts
clean:
	@echo "Cleaning build artifacts..."
	rm -rf bin/
	rm -rf dist/
	rm -f $(COVERAGE_FILE) coverage.html
	go clean -cache
	go clean -testcache

## server: Start HTTP server
server: build
	@echo "Starting HTTP server..."
	./bin/$(BINARY_NAME) server

## migrate-up: Apply database migrations
migrate-up:
	@echo "Applying database migrations..."
	migrate -path internal/database/migrations -database "postgres://$$DB_USER:$$DB_PASSWORD@$$DB_HOST:$$DB_PORT/$$DB_NAME?sslmode=$$DB_SSL_MODE" up

## migrate-down: Rollback database migrations
migrate-down:
	@echo "Rolling back database migrations..."
	migrate -path internal/database/migrations -database "postgres://$$DB_USER:$$DB_PASSWORD@$$DB_HOST:$$DB_PORT/$$DB_NAME?sslmode=$$DB_SSL_MODE" down

## migrate-create: Create new migration (usage: make migrate-create NAME=create_users)
migrate-create:
	@if [ -z "$(NAME)" ]; then echo "Usage: make migrate-create NAME=migration_name"; exit 1; fi
	migrate create -ext sql -dir internal/database/migrations $(NAME)

## db-setup: Initialize PostgreSQL database
db-setup:
	@echo "Setting up PostgreSQL database..."
	createdb -h $$DB_HOST -p $$DB_PORT -U $$DB_USER $$DB_NAME || true
	$(MAKE) migrate-up

## db-reset: Reset database to clean state
db-reset:
	@echo "Resetting database..."
	dropdb -h $$DB_HOST -p $$DB_PORT -U $$DB_USER $$DB_NAME || true
	$(MAKE) db-setup

## db-seed: Populate database with test data
db-seed:
	@echo "Seeding database with test data..."
	go run scripts/seed.go

## install-tools: Install development dependencies
install-tools:
	@echo "Installing development tools..."
	go install github.com/air-verse/air@latest
	go install github.com/golangci/golangci-lint/cmd/golangci-lint@latest
	go install github.com/golang-migrate/migrate/v4/cmd/migrate@latest
	go install golang.org/x/tools/cmd/goimports@latest
	go install github.com/swaggo/swag/cmd/swag@latest
	go install github.com/goreleaser/goreleaser/v2@latest

## check: Run all quality checks
check: fmt-check lint test

## ci: Run CI checks (formatting check, linting, tests)
ci: fmt-check lint test coverage

## build-linux: Cross-compile for Linux
build-linux: clean
	@echo "Building for Linux..."
	GOOS=linux GOARCH=amd64 CGO_ENABLED=0 go build $(LDFLAGS) -o dist/$(BINARY_NAME)-linux-amd64 $(MAIN_PACKAGE)

## build-darwin: Cross-compile for macOS
build-darwin: clean
	@echo "Building for macOS..."
	GOOS=darwin GOARCH=amd64 CGO_ENABLED=0 go build $(LDFLAGS) -o dist/$(BINARY_NAME)-darwin-amd64 $(MAIN_PACKAGE)
	GOOS=darwin GOARCH=arm64 CGO_ENABLED=0 go build $(LDFLAGS) -o dist/$(BINARY_NAME)-darwin-arm64 $(MAIN_PACKAGE)

## build-windows: Cross-compile for Windows
build-windows: clean
	@echo "Building for Windows..."
	GOOS=windows GOARCH=amd64 CGO_ENABLED=0 go build $(LDFLAGS) -o dist/$(BINARY_NAME)-windows-amd64.exe $(MAIN_PACKAGE)

## release: Build release binaries for all platforms using GoReleaser
release:
	@echo "Building release with GoReleaser..."
	goreleaser release --clean

## release-snapshot: Build snapshot release without publishing
release-snapshot:
	@echo "Building snapshot release with GoReleaser..."
	goreleaser release --snapshot --clean

## release-dry: Test release build without publishing
release-dry:
	@echo "Testing release build with GoReleaser..."
	goreleaser release --snapshot --clean --skip=publish

## validate-release: Validate GoReleaser configuration and test build
validate-release:
	@echo "Validating release configuration..."
	@chmod +x scripts/validate-release.sh
	./scripts/validate-release.sh

## check-goreleaser: Quick check of GoReleaser configuration
check-goreleaser:
	@echo "Checking GoReleaser configuration..."
	goreleaser check

## update-goreleaser: Update GoReleaser to v2 and validate
update-goreleaser:
	@echo "Updating GoReleaser to v2..."
	@chmod +x scripts/update-and-validate.sh
	./scripts/update-and-validate.sh

## docker: Build Docker container
docker:
	@echo "Building Docker container..."
	docker build -t maigo:$(VERSION) .

## run-cli: Run CLI with arguments (usage: make run-cli ARGS="auth login")
run-cli: build
	./bin/$(BINARY_NAME) $(ARGS)

## version: Show version information
version:
	@echo "Version: $(VERSION)"
	@echo "Build Time: $(BUILD_TIME)"
	@echo "Git Commit: $(GIT_COMMIT)"
