# Maigo - Wildcard Subdomain URL Shortener

## Project Overview
Maigo is a wildcard subdomain supported URL shortener service built with Zig, featuring a CLI companion with OAuth2 authentication. The project emphasizes a terminal-only, geek-focused experience with comprehensive OAuth2 integration and SSH-based user registration.

## Current Implementation Status

### ✅ Implemented Features
- **Core URL shortening engine** with Base62 encoding and collision detection
- **PostgreSQL database** with full schema and repository pattern
- **OAuth2 server** with authorization code and refresh token flows
- **HTTP server** with wildcard subdomain support and RESTful API
- **CLI authentication tool** with cross-platform token storage
- **SSH server with TUI** for terminal-based user registration
- **Session management** with cookie-based authentication

### 🚧 Partially Implemented
- **OAuth2 database persistence** (some operations stubbed)
- **Protected API endpoints** (basic structure exists)
- **URL management features** (listing, editing incomplete)

### ❌ Not Yet Implemented
- **Let's Encrypt integration** and certificate management
- **Custom domain management** APIs and validation
- **Advanced CLI features** (URL management, analytics)
- **Production configuration** and monitoring

## Requirements

### 1. Core Service (Zig)
- **Wildcard subdomain support**: Allow shortened URLs like `abc.short.ly` where `abc` is the short code
- **Backend**: Built with Zig for high performance
- **Database**: SQLite for lightweight deployment, store URL mappings, user data, custom domains, and certificate status
- **API**: RESTful API for all operations

### 2. CLI Companion
- **OAuth2 client**: Authenticate users with the service
- **URL shortening**: Create short URLs from command line
- **Management**: List, edit, and delete existing short URLs
- **Custom domains**: Manage custom domain bindings

### 3. User System
- **Open registration**: Users can create accounts and their own short URLs
- **Authentication**: OAuth2 flow for secure access
- **Terminal-only**: No web UI, CLI and SSH TUI only for true geeks

### 4. Custom Domain Support
- **Domain binding**: Users can bind their own domains to the service
- **DNS configuration**: Instructions for CNAME setup
- **SSL/TLS**: Automatic certificate provisioning for custom domains
- **Let's Encrypt worker**: Background process for certificate generation and renewal

### 5. SSH-based TUI
- **Registration interface**: Terminal-based user registration system
- **SSH access**: Users can register via SSH connection
- **Interactive forms**: TUI for account creation and management
- **No web interface**: Pure terminal experience for maximum geek factor

### 6. Let's Encrypt Integration
- **Automatic certificate provisioning**: Background worker process
- **Domain validation**: HTTP-01 and DNS-01 challenge support
- **Certificate renewal**: Automated renewal before expiration
- **Wildcard certificates**: Support for wildcard SSL certificates
- **Certificate storage**: Store certificates in SQLite database

## Technical Stack
- **Backend**: Zig (0.14.0+)
- **Database**: PostgreSQL with pg.zig driver
- **SSH**: libssh (external C library, version 0.11.2)
- **Authentication**: OAuth2 with JWT-like tokens
- **CLI**: Zig (cross-platform with XDG config support)
- **TLS**: Let's Encrypt (planned, not yet implemented)
- **Certificate management**: Built-in ACME client (planned)
- **Interface**: Terminal-only (CLI + SSH TUI)

## Architecture Decisions

### Database Change: SQLite → PostgreSQL
The project has moved from SQLite to PostgreSQL to support:
- **Better concurrency** for multi-user access
- **Advanced features** like proper foreign keys and indices
- **Production scalability** with connection pooling
- **ACID compliance** for OAuth2 token operations

### OAuth2 Implementation
- **Authorization Code Grant** with PKCE support
- **Refresh Token Grant** for long-lived access
- **Scope-based permissions** (url:read, url:write)
- **Out-of-band (OOB) redirect** for CLI integration
- **Database-backed token storage** with expiration handling

### Build System
- **Zig build system** with comprehensive targets
- **Cross-platform CLI** with OS-specific token storage
- **External dependency management** (libssh via git submodule)
- **Automated testing** with dedicated test database

## Development Commands
```bash
# First-time setup (initialize submodules and build dependencies)
zig build setup

# Build the service (default: install)
zig build

# Run the service
zig build run

# Run tests
zig build test

# Build in release mode
zig build --release=fast

# Clean build artifacts and dependencies
zig build clean

# Build only libssh dependency
zig build build-libssh

# List available build steps
zig build -l

# Watch mode (rebuild on file changes)
zig build --watch

# Future commands (to be implemented):
# Start Let's Encrypt worker
zig build certbot

# CLI companion
zig build cli
```

## API Endpoints

### ✅ Implemented
- `POST /api/shorten` - Create short URL (public endpoint)
- `GET /{short_code}` - Redirect to target URL (wildcard subdomain support)
- `GET /api/urls` - List user's URLs (protected, basic structure)
- `POST /api/urls` - Create short URL (protected)
- `POST /login` - User authentication with session cookies
- `POST /logout` - Session termination

### 🚧 Partially Implemented
- `GET /api/urls/{id}` - Get specific URL details (returns "Not implemented yet")
- OAuth2 endpoints (server implemented, database persistence incomplete)

### ❌ Planned
- `DELETE /api/urls/:id` - Delete short URL
- `PUT /api/urls/:id` - Update short URL
- `POST /api/domains` - Add custom domain
- `GET /api/domains` - List custom domains
- `DELETE /api/domains/:id` - Remove custom domain

## Next Steps & Recommendations

### Immediate Priorities
1. **Complete OAuth2 database persistence** - Finish authorization code and token storage
2. **Implement remaining API endpoints** - URL management and custom domains
3. **Add Let's Encrypt integration** - Automatic certificate provisioning
4. **Enhance CLI functionality** - URL management commands and analytics

### Tech Stack Evaluation
The current **Zig + PostgreSQL** stack is solid for the project goals:
- **Zig** provides excellent performance and memory safety
- **PostgreSQL** offers production-ready scalability and features
- **libssh** enables the unique SSH-based TUI experience
- **OAuth2 implementation** is comprehensive and well-architected

### Alternative Tech Stack Considerations
If considering a change, evaluate:
- **Go + PostgreSQL** - Similar performance, larger ecosystem
- **Rust + PostgreSQL** - Better ecosystem, steeper learning curve
- **Node.js + PostgreSQL** - Faster development, less performance
- **Keep current stack** - Already significant investment and working well