# Release Process Documentation

This document outlines the release process for Maigo using GitHub Actions and GoReleaser.

## Overview

Maigo uses [GoReleaser](https://goreleaser.com/) to automate the build and release process. The release workflow supports:

- Multi-platform binaries (Linux, macOS, Windows)
- Multi-architecture support (amd64, arm64)
- Docker images published to GitHub Container Registry
- Linux packages (deb, rpm, apk)
- Homebrew tap (optional)
- Automated changelog generation
- Checksums and SBOMs

## Release Types

### 1. Stable Releases

**Trigger**: Push a git tag with format `v*` (e.g., `v1.0.0`, `v1.2.3`)

**Process**:
```bash
# Create and push a tag
git tag v1.0.0
git push origin v1.0.0
```

**Outputs**:
- GitHub release with binaries
- Docker images tagged with version
- Linux packages
- Homebrew formula (if configured)

### 2. Snapshot Releases

**Trigger**: Push to `main` or `develop` branches

**Process**: Automatic on every commit

**Outputs**:
- Build artifacts (available for 30 days)
- No GitHub release created
- No package publishing

### 3. Manual Releases

**Trigger**: Manual workflow dispatch from GitHub Actions UI

**Process**: 
1. Go to GitHub Actions > Release workflow
2. Click "Run workflow"
3. Enter the tag name

## Workflows

### `.github/workflows/release.yml`
- **Purpose**: Full release workflow for tagged versions
- **Triggers**: Git tags (`v*`), manual dispatch
- **Features**: Full GoReleaser build, Docker images, packages

### `.github/workflows/snapshot.yml`
- **Purpose**: Development builds for testing
- **Triggers**: Push to main/develop branches
- **Features**: Snapshot builds, artifact upload

### `.github/workflows/ci.yml`
- **Purpose**: Continuous integration testing
- **Triggers**: All pushes and pull requests
- **Features**: Tests, linting, basic builds

## Configuration Files

### `.goreleaser.yaml`
Main GoReleaser configuration that defines:
- Build targets and flags
- Archive formats
- Docker image configuration
- Package metadata
- Changelog generation
- Release notes templates

### `Dockerfile`
Multi-stage Docker build for minimal production images:
- Based on `scratch` for minimal size
- Includes CA certificates and timezone data
- Default port 8080

## Required Secrets

### GitHub Secrets (Required)
- `GITHUB_TOKEN`: Automatically provided by GitHub Actions

### Optional Secrets
- `HOMEBREW_TAP_GITHUB_TOKEN`: For Homebrew tap publishing (requires separate repository)

## Build Artifacts

### Binaries
- `maigo_<version>_linux_amd64.tar.gz`
- `maigo_<version>_linux_arm64.tar.gz`
- `maigo_<version>_darwin_amd64.tar.gz`
- `maigo_<version>_darwin_arm64.tar.gz`
- `maigo_<version>_windows_amd64.zip`

### Docker Images
- `ghcr.io/yukaii/maigo:latest`
- `ghcr.io/yukaii/maigo:<version>`
- `ghcr.io/yukaii/maigo:v<major>`
- `ghcr.io/yukaii/maigo:v<major>.<minor>`

### Linux Packages
- `maigo_<version>_linux_amd64.deb`
- `maigo_<version>_linux_amd64.rpm`
- `maigo_<version>_linux_amd64.apk`

### Additional Files
- `maigo_<version>_checksums.txt`
- `maigo_<version>_linux_amd64.tar.gz.sbom.json` (Software Bill of Materials)

## Local Development

### Installing GoReleaser
```bash
# Using the Makefile
make install-tools

# Or manually
go install github.com/goreleaser/goreleaser@latest
```

### Testing Releases Locally
```bash
# Test without publishing
make release-dry

# Build snapshot
make release-snapshot

# Test specific configuration
goreleaser check
```

### Manual Release Commands
```bash
# Full release (requires git tag)
make release

# Snapshot release
make release-snapshot

# Dry run (test configuration)
make release-dry
```

## Version Handling

Maigo uses semantic versioning (e.g., `v1.2.3`):
- **Major**: Breaking changes
- **Minor**: New features (backward compatible)
- **Patch**: Bug fixes (backward compatible)

Version information is embedded in the binary using Go's ldflags:
- `main.version`: Git tag or "dev"
- `main.commit`: Git commit hash
- `main.date`: Build timestamp

## Troubleshooting

### Common Issues

1. **GoReleaser fails with "git is dirty"**
   - Ensure working directory is clean
   - Commit all changes before tagging

2. **Docker build fails**
   - Verify Dockerfile syntax
   - Check that all required files are included

3. **Missing GITHUB_TOKEN permissions**
   - Ensure workflow has correct permissions in YAML
   - Check repository settings for Actions permissions

### Debugging
- Check GitHub Actions logs for detailed error messages
- Use `goreleaser check` to validate configuration locally
- Test with `--snapshot` flag to avoid publishing during debugging

## Best Practices

1. **Always test locally first**:
   ```bash
   goreleaser release --snapshot --clean
   ```

2. **Use semantic versioning for tags**:
   ```bash
   git tag v1.2.3
   ```

3. **Review generated release notes before final publication**

4. **Keep secrets secure and rotate periodically**

5. **Test Docker images after release**:
   ```bash
   docker run ghcr.io/yukaii/maigo:latest --version
   ```

## Additional Resources

- [GoReleaser Documentation](https://goreleaser.com/)
- [GitHub Actions Documentation](https://docs.github.com/en/actions)
- [Semantic Versioning](https://semver.org/)
- [Docker Best Practices](https://docs.docker.com/develop/dev-best-practices/)
