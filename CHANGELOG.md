# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- GitHub Actions workflow for automated releases
- GoReleaser configuration for multi-platform builds
- Docker image publishing to GitHub Container Registry
- Linux packages (deb, rpm, apk)
- Homebrew tap support (optional)
- Automated changelog generation
- Comprehensive release documentation

### Changed
- Separated CI and release workflows for better organization
- Updated build process to use GoReleaser
- Improved Dockerfile for minimal production images

### Developer Experience
- Added `make validate-release` command
- Added `make release-snapshot` for testing
- Added `make release-dry` for configuration testing
- Updated setup process to include GoReleaser

## Release Process

This project uses [GoReleaser](https://goreleaser.com/) for automated releases.

### Creating a Release

1. Update the version and changelog
2. Create and push a git tag:
   ```bash
   git tag v1.0.0
   git push origin v1.0.0
   ```
3. GitHub Actions will automatically:
   - Build binaries for all platforms
   - Create Docker images
   - Generate Linux packages
   - Create a GitHub release with changelog

### Testing Releases

Before creating a tag, test the release process:

```bash
# Validate configuration
make validate-release

# Test full build without publishing
make release-snapshot
```
