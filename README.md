# Maigo - Go Implementation

A wildcard subdomain supported URL shortener service built with Go.

## Quick Start

```bash
# Setup development environment
make setup

# Start development server
make dev

# Run tests
make test
```

## Features

- 🌐 **Wildcard Subdomain Support** - URLs like `abc.maigo.dev`
- 🔐 **OAuth2 Authentication** - Secure API access
- 💻 **CLI Companion** - Command-line URL management
- 🖥️ **SSH TUI Registration** - Terminal-based user registration
- 🗄️ **PostgreSQL Backend** - Robust data persistence
- ⚡ **High Performance** - Built with Gin framework

## Architecture

- **HTTP Server**: Gin web framework
- **CLI**: Cobra command framework  
- **TUI**: Bubble Tea + Wish SSH integration
- **Database**: PostgreSQL with pgx driver
- **Authentication**: OAuth2 + JWT tokens

## Development

See [docs/development.md](docs/development.md) for detailed setup instructions.

## API Documentation

API documentation is available at `/docs` when running the server, or see [docs/api.md](docs/api.md).

## License

MIT License - see [LICENSE](LICENSE) for details.
