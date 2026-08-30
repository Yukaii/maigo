# Changelog

All notable changes to Maigo will be documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.0.0/), and releases use
[Semantic Versioning](https://semver.org/).

## [Unreleased]

### Production-readiness follow-up

- Added explicit CORS origin configuration with debug-only wildcard behavior.
- Added production-mode validation for debug settings and JWT placeholders.
- Wired Redis into server startup and added atomic distributed rate limiting
  with auth-endpoint protection and a bounded in-process fallback.
- Added transactional click-event recording and UTC day-bucketed URL
  statistics.
- Added configurable, batched click-event retention and Prometheus-format
  operational counters for redirect and cleanup failures.

### Added

- Pinned Go, Air, golangci-lint, migrate, GoReleaser, and goimports tooling in
  `mise.toml`.
- End-to-end PostgreSQL coverage for bcrypt authentication, OAuth/PKCE,
  refresh rotation, logout, and expired-link behavior.
- A current project status report and route-accurate OpenAPI specification.

### Changed

- Documented the project as a prototype with explicit deployment limitations.
- Updated CI to use pinned tool versions and a configured integration database.
- Wired Compose base-domain, TLS, rate-limit, and database settings through to
  the application.
- Documented the statistics timeline as stored click-event buckets and called
  out the remaining click-event retention gap.
- Documented retention settings and private metrics scraping in the deployment
  and API guides.

### Fixed

- Removed the hard-coded OAuth authorization-code user and enforced PKCE S256.
- Replaced plaintext passwords with bcrypt hashes.
- Added stateful refresh-token rotation and real refresh-session revocation.
- Enforced exact/narrowly-scoped redirect URI matching and one-time auth codes.
- Enforced URL expiration on redirects, fixed dynamic SQL updates, corrected
  OAuth template rendering, and fixed CLI help/config handling.

See [`docs/RELEASE.md`](docs/RELEASE.md) for the release workflow.
