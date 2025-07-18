#!/bin/bash

# Script to validate GoReleaser configuration and test build
# Usage: ./scripts/validate-release.sh

set -e

echo "🔍 Validating GoReleaser configuration..."

# Check if goreleaser is installed
if ! command -v goreleaser &> /dev/null; then
    echo "❌ GoReleaser not found. Installing..."
    go install github.com/goreleaser/goreleaser@latest
fi

# Validate configuration
echo "📝 Checking GoReleaser configuration..."
goreleaser check

# Test build without publishing
echo "🏗️ Testing build (snapshot mode)..."
goreleaser build --snapshot --clean --single-target

# Check if binary was built successfully
if [ -f "dist/maigo_linux_amd64_v1/maigo" ]; then
    echo "✅ Build successful!"
    echo "📦 Testing binary..."
    ./dist/maigo_linux_amd64_v1/maigo --version
else
    echo "❌ Build failed - binary not found"
    exit 1
fi

echo "🎉 All validations passed!"
echo ""
echo "To create a release:"
echo "  1. Create and push a tag: git tag v1.0.0 && git push origin v1.0.0"
echo "  2. GitHub Actions will automatically create the release"
echo ""
echo "To test locally:"
echo "  make release-snapshot  # Full snapshot build"
echo "  make release-dry       # Test without publishing"
