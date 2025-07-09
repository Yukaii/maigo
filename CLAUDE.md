# Maigo - Wildcard Subdomain URL Shortener

## Project Overview
Maigo is a wildcard subdomain supported URL shortener service built with Zig, featuring a CLI companion with OAuth2 authentication.

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
- **Backend**: Zig
- **Database**: SQLite (embedded, single file)
- **Authentication**: OAuth2
- **CLI**: Zig (cross-platform)
- **TLS**: Let's Encrypt (automated)
- **Certificate management**: Built-in ACME client
- **Interface**: Terminal-only (CLI + SSH TUI)

## Development Commands
```bash
# Build the service (default: install)
zig build

# Run the service
zig build run

# Run tests
zig build test

# Build in release mode
zig build --release=fast

# Watch mode (rebuild on file changes)
zig build --watch

# List available build steps
zig build -l

# Future commands (to be implemented):
# Start Let's Encrypt worker
zig build certbot

# SSH TUI server
zig build ssh-server

# CLI companion
zig build cli
```

## API Endpoints (Planned)
- `POST /api/shorten` - Create short URL
- `GET /api/urls` - List user's URLs
- `DELETE /api/urls/:id` - Delete short URL
- `POST /api/domains` - Add custom domain
- `GET /api/domains` - List custom domains