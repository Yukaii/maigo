# Maigo - Wildcard Subdomain URL Shortener

## Project Overview
Maigo is a wildcard subdomain supported URL shortener service built with **Go**, featuring a CLI companion with OAuth2 authentication. The project emphasizes a terminal-only, geek-focused experience with comprehensive OAuth2 integration and SSH-based user registration.

## Tech Stack Migration: Zig → Go

### Why Switch to Go?
After comprehensive research, **Go provides significant advantages** for this type of application:

**1. Superior CLI Framework Support**
- **Cobra** - Industry-standard CLI framework used by Kubernetes, Hugo, GitHub CLI
- Automatic help generation, command completion, nested subcommands
- POSIX-compliant flags with powerful argument parsing

**2. Mature HTTP Server Ecosystem**  
- **Gin** - High-performance web framework (40x faster than Martini)
- Built-in middleware support, JSON validation, route grouping
- Excellent performance with radix tree routing and minimal memory footprint

**3. Advanced TUI & SSH Integration**
- **Bubble Tea** - Modern TUI framework with 33k+ GitHub stars
- **Wish** - SSH server framework designed specifically for Bubble Tea apps
- Native SSH middleware for serving TUI applications over secure connections

**4. Production-Ready Ecosystem**
- Superior PostgreSQL drivers (pgx vs lib/pq)
- Better testing frameworks and tooling
- Extensive community support and documentation

## Current Implementation Status (Zig - To Be Migrated)

### ✅ Implemented Features (Zig)
- **Core URL shortening engine** with Base62 encoding and collision detection
- **PostgreSQL database** with full schema and repository pattern  
- **OAuth2 server** with authorization code and refresh token flows
- **HTTP server** with wildcard subdomain support and RESTful API
- **CLI authentication tool** with cross-platform token storage
- **SSH server with TUI** for terminal-based user registration
- **Session management** with cookie-based authentication

### � Migration Plan Status
- **[ ] Go project structure setup** with modern Go conventions
- **[ ] Cobra CLI implementation** replacing current Zig CLI
- **[ ] Gin HTTP server** replacing custom Zig HTTP implementation
- **[ ] Bubble Tea + Wish SSH TUI** replacing libssh integration
- **[ ] Go PostgreSQL migration** from Zig pg.zig to Go pgx
- **[ ] OAuth2 library integration** using Go oauth2 packages
- **[ ] Testing framework setup** with Go testing and testify

### ❌ Not Yet Implemented (Either Stack)
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

## Technical Stack (Revised for Go)

### Backend Architecture
- **Language**: Go (1.21+)
- **HTTP Framework**: Gin (high-performance web framework)
- **Database**: PostgreSQL with pgx driver (modern, fast, feature-rich)
- **Authentication**: OAuth2 with Go oauth2 package
- **Session Management**: Gorilla sessions or Gin-contrib sessions

### CLI & TUI Components  
- **CLI Framework**: Cobra (command structure, flags, help generation)
- **TUI Framework**: Bubble Tea (terminal UI rendering and event handling)
- **SSH Server**: Wish (SSH middleware for Bubble Tea apps)
- **Configuration**: Viper (configuration management, pairs well with Cobra)

### Data & Storage
- **PostgreSQL Driver**: pgx/v5 (recommended over lib/pq for new projects)
- **Migration**: golang-migrate/migrate (database schema management)
- **Connection Pooling**: pgxpool (built-in with pgx)
- **Query Builder**: Squirrel or raw SQL (for performance)

### Security & Authentication
- **OAuth2 Implementation**: golang.org/x/oauth2 + custom server logic  
- **JWT Tokens**: golang-jwt/jwt for stateless authentication
- **Password Hashing**: bcrypt or argon2 (crypto/bcrypt or go-password-validator)
- **SSH Keys**: golang.org/x/crypto/ssh for SSH key management

### Development & Deployment
- **Build System**: Go modules with Makefile
- **Testing**: testify framework + httptest for HTTP testing
- **Linting**: golangci-lint with comprehensive rule set
- **Documentation**: go doc + custom documentation generation

### External Dependencies
- **Let's Encrypt**: lego (ACME client for certificate automation)
- **Domain Validation**: net package for DNS lookups
- **Logging**: slog (Go 1.21+ structured logging) or logrus
- **Configuration**: environment variables + YAML/JSON config files

## Go Framework Research Summary

### Cobra CLI Framework
**Features & Capabilities:**
- **Subcommand Structure**: `app server`, `app auth login`, `app shorten <url>`
- **POSIX-Compliant Flags**: Short (`-h`) and long (`--help`) flag support
- **Automatic Help Generation**: Built-in help system with usage examples
- **Shell Completion**: Auto-generated completion for bash, zsh, fish, PowerShell
- **Flag Inheritance**: Global, local, and cascading flags across command tree
- **Command Aliases**: Backward compatibility when refactoring commands
- **Validation**: Built-in argument validation and required flag checking

**Used By**: Kubernetes, Hugo, GitHub CLI, Docker CLI, Helm

### Gin Web Framework  
**Performance & Features:**
- **Speed**: Up to 40x faster than Martini due to httprouter
- **Radix Tree Routing**: Efficient URL pattern matching
- **Middleware Chain**: Logger, CORS, recovery, authentication middleware
- **JSON Handling**: Built-in JSON binding, validation, and rendering
- **Route Groups**: Organize endpoints by version or functionality
- **Error Management**: Centralized error collection and handling
- **Template Rendering**: HTML, XML, JSON rendering support

**Middleware Ecosystem**: Rate limiting, CORS, JWT auth, compression, logging

### Bubble Tea TUI Framework
**Architecture & Features:**
- **Elm Architecture**: Model-Update-View pattern for predictable state management
- **Event-Driven**: Keyboard, mouse, resize, and custom events
- **Composable**: Build complex UIs from reusable components  
- **SSH Compatible**: Works seamlessly over SSH connections
- **Cross-Platform**: Windows, macOS, Linux terminal support
- **Performance**: Framerate-based rendering with efficient updates

**Ecosystem**: Bubbles (UI components), Lip Gloss (styling), Harmonica (animations)

### Wish SSH Server Framework
**SSH App Capabilities:**
- **Bubble Tea Integration**: Direct middleware for serving TUI apps over SSH
- **Authentication**: SSH key-based authentication with custom logic
- **Session Management**: Per-connection isolation and state management
- **Git Server Support**: Built-in Git protocol support for SSH Git operations
- **Middleware Architecture**: Composable middleware for logging, access control
- **No OpenSSH Required**: Pure Go implementation, self-contained

**Real-World Examples**: Soft Serve (Git), Wishlist (SSH directory), various TUI apps

### PostgreSQL Driver Comparison (pgx vs lib/pq)
**pgx Advantages:**
- **Active Development**: lib/pq is in maintenance mode, pgx is actively developed
- **Performance**: Significantly faster than lib/pq
- **PostgreSQL-Specific Features**: Arrays, JSON/JSONB, custom types, LISTEN/NOTIFY
- **Connection Pooling**: Built-in pgxpool with advanced pool management
- **Prepared Statements**: Automatic prepared statement caching
- **Type Safety**: Better type mapping between Go and PostgreSQL

**Migration Path**: Direct replacement with improved API design

## Architecture Decisions

### Migration Rationale: Zig → Go

**Development Velocity & Ecosystem**
- **Zig**: Bleeding-edge language with limited ecosystem and documentation
- **Go**: Mature ecosystem with comprehensive documentation and community support
- **Time to Market**: Go's extensive libraries significantly reduce development time

**Framework Maturity**
- **Zig**: Requires custom implementation of HTTP servers, CLI parsing, TUI systems
- **Go**: Battle-tested frameworks (Gin, Cobra, Bubble Tea) used in production by major companies
- **Maintenance**: Lower maintenance burden with established, well-supported libraries

**Team Productivity**  
- **Learning Curve**: Go has gentler learning curve and broader developer adoption
- **Debugging**: Superior debugging tools and IDE support
- **Testing**: Comprehensive testing ecosystem with benchmarking and race detection

### Technical Architecture (Go Implementation)

**HTTP Server (Gin)**
```go
// Example structure
r := gin.Default()
r.Use(middleware.CORS(), middleware.RateLimit(), middleware.Logger())

api := r.Group("/api/v1")
api.Use(middleware.OAuth2())
api.POST("/urls", handlers.CreateShortURL)
api.GET("/urls", handlers.ListURLs)

r.GET("/:code", handlers.RedirectToURL) // Wildcard subdomain support
```

**CLI Structure (Cobra)**
```go
// Command hierarchy
maigo
├── server          # Start HTTP/SSH servers  
├── auth            # OAuth2 authentication
│   ├── login       # Username/password login
│   ├── logout      # Session termination
│   └── status      # Show auth status
├── shorten <url>   # Create short URL
├── list            # List user URLs
└── config          # Configuration management
```

**SSH TUI (Bubble Tea + Wish)**
```go
// SSH server with TUI middleware
s, err := wish.NewServer(
    wish.WithAddress(":2222"),
    wish.WithHostKeyPath("host_key"),
    wish.WithMiddleware(
        bubbletea.Middleware(func(s ssh.Session) tea.Model {
            return models.NewRegistrationTUI()
        }),
        logging.Middleware(),
    ),
)
```

**Database Integration (pgx)**
```go
// Connection pool with pgx
config, _ := pgxpool.ParseConfig(databaseURL)
config.MaxConns = 10
config.MaxConnIdleTime = time.Minute * 5

pool, err := pgxpool.NewWithConfig(ctx, config)

// Query with prepared statements
rows, err := pool.Query(ctx, "SELECT id, url FROM urls WHERE user_id = $1", userID)
```

### OAuth2 Implementation Strategy
- **Authorization Code Flow**: Full OAuth2 server implementation
- **Refresh Tokens**: Long-lived sessions with secure refresh mechanism  
- **Scopes**: Granular permissions (url:read, url:write, admin:manage)
- **Out-of-Band (OOB)**: CLI-friendly redirect handling
- **Token Storage**: Secure token persistence with cross-platform config directories

## Development Commands (Go Implementation)

```bash
# Project initialization
go mod init github.com/yukaii/maigo
go mod tidy

# Development workflow
make dev          # Start development server with hot reload
make build        # Build all binaries (server + CLI)
make test         # Run all tests with coverage
make lint         # Run golangci-lint
make fmt          # Format code with gofmt

# Server operations  
make server       # Start HTTP server (port 8080)
make ssh-server   # Start SSH TUI server (port 2222)
make migrate-up   # Apply database migrations
make migrate-down # Rollback database migrations

# CLI operations
./maigo auth login                    # Username/password authentication
./maigo auth url                      # Get OAuth2 authorization URL  
./maigo auth token <code>             # Exchange auth code for token
./maigo shorten https://example.com   # Create short URL
./maigo list                          # List user's URLs
./maigo config set server.host 0.0.0.0  # Update configuration

# Database management
make db-setup     # Initialize PostgreSQL database
make db-reset     # Reset database to clean state  
make db-seed      # Populate with test data
make db-backup    # Create database backup

# Testing & Quality
make test-unit    # Unit tests only
make test-integration  # Integration tests with test database
make test-coverage     # Generate coverage report
make benchmark         # Run performance benchmarks

# Build & Release
make build-linux      # Cross-compile for Linux
make build-darwin     # Cross-compile for macOS  
make build-windows    # Cross-compile for Windows
make release          # Build release binaries for all platforms
make docker          # Build Docker container

# Development tools
make install-tools   # Install development dependencies
make check          # Run all quality checks (lint, test, fmt)
make clean          # Clean build artifacts

# Future commands (to be implemented):
make certbot        # Start Let's Encrypt certificate manager
make docs           # Generate API documentation
```

## Project Structure (Go Implementation)

```
maigo/
├── cmd/                          # Application entry points
│   ├── server/main.go           # HTTP/SSH server binary  
│   └── maigo/main.go            # CLI binary
├── internal/                     # Private application code
│   ├── server/                  # HTTP server implementation
│   │   ├── handlers/            # HTTP route handlers
│   │   ├── middleware/          # HTTP middleware (auth, CORS, etc.)
│   │   └── router.go            # Route definitions
│   ├── ssh/                     # SSH TUI server
│   │   ├── tui/                 # Bubble Tea models
│   │   └── server.go            # Wish SSH server setup
│   ├── database/                # Database layer
│   │   ├── migrations/          # SQL migration files
│   │   ├── models/              # Data models
│   │   └── queries/             # SQL queries
│   ├── oauth/                   # OAuth2 implementation
│   │   ├── server.go            # OAuth2 server logic
│   │   └── client.go            # OAuth2 client helpers
│   ├── shortener/               # URL shortening logic
│   │   ├── encoder.go           # Base62 encoding
│   │   └── service.go           # Shortening service
│   └── config/                  # Configuration management
│       └── config.go            # Viper configuration setup
├── pkg/                         # Public library code
│   ├── auth/                    # Authentication utilities
│   └── crypto/                  # Cryptographic utilities  
├── api/                         # API definitions
│   ├── openapi.yaml             # OpenAPI specification
│   └── client/                  # Generated API client
├── web/                         # Static assets (minimal)
│   └── assets/                  # CSS, JS for OAuth pages
├── scripts/                     # Build and deployment scripts
│   ├── setup.sh                 # Environment setup
│   ├── migrate.sh               # Database migration script
│   └── deploy.sh                # Deployment script
├── configs/                     # Configuration files
│   ├── config.dev.yaml          # Development configuration
│   ├── config.prod.yaml         # Production configuration
│   └── docker-compose.yml       # Development environment
├── docs/                        # Documentation
│   ├── api.md                   # API documentation
│   ├── deployment.md            # Deployment guide
│   └── development.md           # Development setup
├── tests/                       # Test files
│   ├── integration/             # Integration tests
│   ├── fixtures/                # Test data
│   └── mocks/                   # Mock implementations
├── go.mod                       # Go module definition
├── go.sum                       # Go module checksums
├── Makefile                     # Build automation
├── Dockerfile                   # Container definition
├── .golangci.yml               # Linter configuration
└── README.md                   # Project documentation
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

## Migration Implementation Plan

### Phase 1: Foundation Setup (Week 1-2)
```markdown
- [ ] Initialize Go module and project structure
- [ ] Setup development environment (Docker, PostgreSQL, tools)
- [ ] Configure Makefile and development scripts
- [ ] Setup golangci-lint, testing framework, and CI/CD
- [ ] Database schema migration from Zig to Go migration system
- [ ] Basic PostgreSQL connection with pgx
```

### Phase 2: Core Services Migration (Week 3-4)  
```markdown
- [ ] Implement URL shortener service with Base62 encoding
- [ ] Create database models and repository pattern
- [ ] Setup Gin HTTP server with basic routing
- [ ] Implement wildcard subdomain support
- [ ] Add middleware for logging, CORS, recovery
- [ ] Create basic API endpoints (shorten, redirect)
```

### Phase 3: Authentication System (Week 5-6)
```markdown
- [ ] Implement OAuth2 server with authorization code flow
- [ ] Setup session management and cookie handling
- [ ] Create OAuth2 database models and persistence
- [ ] Implement refresh token flow
- [ ] Add JWT token validation middleware
- [ ] Create protected API endpoints
```

### Phase 4: CLI Application (Week 7-8)
```markdown
- [ ] Setup Cobra CLI framework structure
- [ ] Implement authentication commands (login, logout, status)
- [ ] Create OAuth2 client flow for CLI
- [ ] Add URL management commands (shorten, list, delete)
- [ ] Implement cross-platform configuration storage
- [ ] Add shell completion support
```

### Phase 5: SSH TUI System (Week 9-10)
```markdown
- [ ] Setup Wish SSH server framework
- [ ] Create Bubble Tea TUI models for registration
- [ ] Implement SSH key authentication
- [ ] Create user registration and management flow
- [ ] Add SSH middleware for logging and access control
- [ ] Integrate TUI with database operations
```

### Phase 6: Testing & Polish (Week 11-12)
```markdown
- [ ] Comprehensive unit test coverage (>80%)
- [ ] Integration tests for all API endpoints  
- [ ] SSH TUI interaction testing
- [ ] Performance benchmarking and optimization
- [ ] Security audit and penetration testing
- [ ] Documentation and deployment guides
```

### Phase 7: Advanced Features (Week 13-16)
```markdown
- [ ] Let's Encrypt integration with lego library
- [ ] Custom domain management APIs
- [ ] URL analytics and statistics  
- [ ] Rate limiting and abuse prevention
- [ ] Admin dashboard and monitoring
- [ ] Production deployment and monitoring setup
```

## Next Steps & Recommendations

### Immediate Action Items
1. **Initialize Go Project Structure** - Set up modern Go project layout
2. **Database Migration Strategy** - Export existing PostgreSQL schema to Go migrations  
3. **Development Environment** - Docker Compose with PostgreSQL, development tools
4. **Framework Integration** - Start with Gin HTTP server and basic routing

### Go Package Dependencies
```go
// Core dependencies
github.com/gin-gonic/gin                    // HTTP web framework
github.com/spf13/cobra                      // CLI framework
github.com/charmbracelet/bubbletea          // TUI framework
github.com/charmbracelet/wish               // SSH server framework
github.com/jackc/pgx/v5                     // PostgreSQL driver
github.com/golang-migrate/migrate/v4        // Database migrations

// Supporting libraries  
github.com/spf13/viper                      // Configuration management
github.com/stretchr/testify                 // Testing framework
golang.org/x/oauth2                         // OAuth2 client
github.com/golang-jwt/jwt/v5                // JWT tokens
github.com/go-playground/validator/v10      // Input validation
github.com/rs/cors                          // CORS middleware
go.uber.org/zap                            // Structured logging

// Optional/Future
github.com/go-acme/lego                     // Let's Encrypt client
github.com/prometheus/client_golang         // Metrics collection
github.com/gorilla/sessions                 // Session management
```

### Technical Evaluation Summary

The **Go tech stack migration** provides significant advantages:

**✅ Proven Production Readiness**
- Frameworks used by Kubernetes, Docker, GitHub CLI
- Battle-tested in high-scale production environments
- Extensive monitoring and observability tools

**✅ Developer Experience**
- Comprehensive documentation and community support
- Superior IDE support with Language Server Protocol
- Rich ecosystem of testing and development tools

**✅ Performance & Scalability**  
- Gin framework provides excellent HTTP performance
- pgx driver offers superior PostgreSQL performance
- Built-in concurrency with goroutines and channels

**✅ Maintenance & Longevity**
- Stable APIs with backward compatibility guarantees
- Active maintenance and security updates
- Lower risk of framework abandonment

The **Go implementation** will significantly reduce development time while providing a more robust, maintainable, and scalable foundation for the Maigo URL shortener service.

### Migration Timeline
- **Estimated Duration**: 3-4 months for complete migration  
- **MVP Milestone**: 6-8 weeks (Core functionality working)
- **Production Ready**: 12-16 weeks (Including advanced features)
- **Risk Level**: Low (Mature ecosystem, well-documented patterns)