.PHONY: help setup build test test-unit test-integration coverage lint fmt fmt-check clean server docker run-cli check release release-snapshot release-dry check-goreleaser

.DEFAULT_GOAL := help

GO_VERSION := 1.25.14
BINARY_NAME := maigo
MAIN_PACKAGE := ./cmd/$(BINARY_NAME)
COVERAGE_FILE := coverage.out
BUILD_TIME := $(shell date -u +"%Y-%m-%dT%H:%M:%SZ")
GIT_COMMIT := $(shell git rev-parse --short HEAD 2>/dev/null || echo unknown)
VERSION := $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
MISE := mise exec --
LDFLAGS := -ldflags "-X main.version=$(VERSION) -X main.commit=$(GIT_COMMIT) -X main.date=$(BUILD_TIME)"

## help: Show available commands
help:
	@echo "Available commands:"
	@sed -n 's/^##//p' $(MAKEFILE_LIST) | column -t -s ':' | sed -e 's/^/ /'

## setup: Install the pinned toolchain and download dependencies
setup:
	@mise install
	$(MISE) go mod download
	$(MISE) go mod tidy
	@if [ ! -f .env ]; then cp .env.example .env; fi

## build: Build bin/maigo
build:
	@mkdir -p bin
	CGO_ENABLED=0 $(MISE) go build $(LDFLAGS) -o bin/$(BINARY_NAME) $(MAIN_PACKAGE)

## test: Run unit and integration tests with the local SQLite database
test: test-unit test-integration

## test-unit: Run internal tests with the race detector
test-unit:
	$(MISE) go test -race -short ./internal/...

## test-integration: Run the end-to-end HTTP suite without external services
test-integration:
	$(MISE) go test -race ./tests/...

## coverage: Generate coverage.out and coverage.html
coverage:
	$(MISE) go test -race -coverprofile=$(COVERAGE_FILE) ./...
	$(MISE) go tool cover -html=$(COVERAGE_FILE) -o coverage.html

## lint: Run the pinned golangci-lint
lint:
	$(MISE) golangci-lint run

## fmt: Format Go sources and module files
fmt:
	$(MISE) gofmt -s -w $$(rg --files -g '*.go')
	$(MISE) goimports -w $$(rg --files -g '*.go')
	$(MISE) go mod tidy

## fmt-check: Fail if Go sources are not formatted or imports are untidy
fmt-check:
	@test -z "$$($(MISE) gofmt -s -l $$(rg --files -g '*.go'))"
	@test -z "$$($(MISE) goimports -l $$(rg --files -g '*.go'))"

## clean: Remove local build and coverage artifacts
clean:
	rm -rf bin dist coverage.out coverage.html

## server: Build and start the HTTP server
server: build
	./bin/$(BINARY_NAME) server

## docker: Build the production image
docker:
	docker build -f Dockerfile.production -t maigo:$(VERSION) .

## run-cli: Run the built CLI (usage: make run-cli ARGS="shorten example.com")
run-cli: build
	./bin/$(BINARY_NAME) $(ARGS)

## check: Run formatting, lint, and all tests
check: fmt-check lint test

## release: Create a tagged release with GoReleaser
release:
	$(MISE) goreleaser release --clean

## release-snapshot: Build local snapshot artifacts
release-snapshot:
	$(MISE) goreleaser release --snapshot --clean

## release-dry: Validate release packaging without publishing
release-dry:
	$(MISE) goreleaser release --snapshot --clean --skip=publish

## check-goreleaser: Validate the GoReleaser configuration
check-goreleaser:
	$(MISE) goreleaser check
