
# Maigo - Terminal-First URL Shortener

Maigo is a **terminal-first URL shortener** built with Go, designed for a geek-focused, CLI-first experience. It features a modern Go project structure, secure OAuth 2.0 authentication (with PKCE for CLI), and production-ready architecture with PostgreSQL and comprehensive testing.

## Installation

### Download Binary (Recommended)

Download the latest release for your platform from the [Releases page](https://github.com/yukaii/maigo/releases).

```bash
# Example for Linux/macOS
curl -L https://github.com/yukaii/maigo/releases/latest/download/maigo_<version>_<os>_<arch>.tar.gz | tar xz
sudo mv maigo /usr/local/bin/
```

### Using Go Install

```bash
go install github.com/yukaii/maigo/cmd/maigo@latest
```

### Using Homebrew (macOS/Linux)

```bash
brew install yukaii/tap/maigo
```

### Docker

```bash
# Run server
docker run -p 8080:8080 ghcr.io/yukaii/maigo:latest server

# Run CLI commands
docker run ghcr.io/yukaii/maigo:latest --help
```

### Linux Packages

Download `.deb`, `.rpm`, or `.apk` packages from the [Releases page](https://github.com/yukaii/maigo/releases).

```bash
# Debian/Ubuntu
sudo dpkg -i maigo_<version>_linux_amd64.deb

# RHEL/CentOS/Fedora
sudo rpm -i maigo_<version>_linux_amd64.rpm

# Alpine
sudo apk add --allow-untrusted maigo_<version>_linux_amd64.apk
```

## Quick Start

```bash
# Setup development environment
make setup

# Start development server with hot reload
make dev

# Run all tests
make test
```

## Features

- 🔐 **OAuth 2.0 Authentication (PKCE)** – Secure, standards-compliant OAuth 2.0 with PKCE for CLI
- 💻 **CLI-First Workflow** – All URL management via imperative CLI commands
- 🌐 **Wildcard Subdomain Support** – Short URLs like `abc.maigo.dev`
- �️ **PostgreSQL Backend** – Robust, production-ready data persistence
- ⚡ **High Performance** – Built with Gin web framework
- 📦 **12-Factor App Configuration** – ENV vars, CLI flags, config file (with clear precedence)
- 🧪 **Comprehensive Testing** – Integration and unit tests, automated DB setup
- 📝 **No Web Dashboard** – Minimal web UI for OAuth only; all management via CLI

## Architecture

- **Backend**: Go (Gin web framework)
- **CLI**: Cobra framework (imperative commands)
- **Database**: PostgreSQL (pgx driver, migrations)
- **Authentication**: OAuth 2.0 (PKCE, JWT tokens)
- **Testing**: Testify, automated DB setup

## CLI Command Structure

```bash
# Authentication (OAuth 2.0 with PKCE)
maigo auth register <username> <email>   # Register via CLI with browser-based OAuth
maigo auth login <username>              # Login with browser-based OAuth
maigo auth logout                        # Clear local OAuth tokens
maigo auth status                        # Show current OAuth authentication status

# URL Management
maigo shorten <url>                      # Create short URL
maigo shorten <url> --custom <code>      # Create with custom short code
maigo list                               # List all user URLs
maigo list --limit 10                    # List recent 10 URLs
maigo get <short-code>                   # Get URL details
maigo delete <short-code>                # Delete URL
maigo delete <short-code> --force        # Delete without confirmation
maigo stats <short-code>                 # Show URL analytics

# Server Operations
maigo server                             # Start HTTP server

# System Commands
maigo version                            # Show version
maigo config                             # Show configuration
```

## 12-Factor App Configuration

Maigo supports configuration via environment variables (highest priority), command-line flags, and config file (lowest priority).

**Environment Variables Example:**

```bash
export DATABASE_URL="postgres://username:password@host:port/database?sslmode=require"
export PORT=8080
export JWT_SECRET="your-secure-jwt-secret"
maigo server
```

**Command-Line Flags Example:**

```bash
maigo server --database-url "postgres://user:pass@host:port/db?sslmode=require" --host 0.0.0.0
```

**Config File Example:** (`config/config.yaml`)

```yaml
database:
  host: localhost
  port: 5432
  name: maigo
  user: postgres
  password: password
  ssl_mode: disable
server:
  port: 8080
  host: 127.0.0.1
```

## Development Commands

```bash
make dev          # Start development server with hot reload
make build        # Build the binary
make test         # Run all tests
make server       # Start HTTP server (port 8080)
make db-setup     # Initialize PostgreSQL database
make test-setup   # Setup test database and run tests
```

## API Endpoints

**Core Functionality:**
- `GET /{short_code}` – Redirect to target URL with hit tracking
- `GET /health` – Health check
- `GET /health/ready` – Database health check

**OAuth 2.0 Authentication:**
- `GET /oauth/authorize` – OAuth 2.0 authorization endpoint (HTML form)
- `POST /oauth/authorize` – Process authorization (PKCE support)
- `POST /oauth/token` – Token exchange (authorization code → access token)
- `POST /oauth/revoke` – Token revocation
- `POST /api/v1/auth/register` – User registration (OAuth 2.0)
- `POST /api/v1/auth/login` – User login (OAuth 2.0)
- `POST /api/v1/auth/refresh` – Refresh access token

**URL Management (Protected):**
- `POST /api/v1/urls` – Create short URL (auth required)
- `GET /api/v1/urls` – List user URLs (auth required)
- `GET /api/v1/urls/{id}` – Get URL details (auth required)
- `DELETE /api/v1/urls/{id}` – Delete URL (auth required)

## Project Structure

```
maigo/
├── cmd/
│   └── maigo/main.go            # CLI application with server command
├── internal/
│   ├── server/handlers/         # HTTP handlers (OAuth2, URL)
│   ├── database/models/         # Data models
│   ├── oauth/                   # OAuth2 server
│   ├── shortener/               # URL shortening logic
│   └── config/                  # Configuration
├── config/
│   └── config.yaml              # Application configuration
├── tests/
│   └── integration_test.go      # Integration tests
├── go.mod                       # Go dependencies
└── Makefile                     # Build automation
```

## License

MIT License – see [LICENSE](LICENSE) for details.
