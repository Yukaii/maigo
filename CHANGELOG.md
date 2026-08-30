# Changelog

All notable changes to Maigo are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.0.0/).

## [Unreleased]

### Maigo Core 1.0

- Reframed the project as a small single-owner self-hosted shortener.
- Replaced PostgreSQL and external migrations with one SQLite database file
  initialized on startup.
- Replaced browser OAuth, users, JWTs, and sessions with one API key.
- Kept custom aliases, optional expiry, public redirects, lifetime hit counts,
  list/inspect/stats/delete operations, and a script-friendly CLI.
- Added a local stdio MCP server with five URL-management tools.
- Simplified Compose, CI, release metadata, backups, deployment guidance, and
  the OpenAPI contract around the Core topology.
- Added self-contained race-enabled SQLite integration coverage.

The previous production-hardening implementation remains available on the
`codex/production-hardening` branch as historical reference. It is not the
Core runtime.
