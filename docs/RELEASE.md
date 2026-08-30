# Release process

Maigo Core uses GoReleaser v2 for tagged releases and local snapshots. The
application artifact is a single statically linked CLI/server binary; the
Compose image is built from `Dockerfile.production`.

## Local checks

```bash
make setup
make fmt-check
make test
make lint
make check-goreleaser
```

Validate packaging without publishing:

```bash
make release-dry
```

## Stable release

After the checks pass and intended changes are committed:

```bash
git tag vX.Y.Z
git push origin vX.Y.Z
```

The release workflow runs GoReleaser and publishes binary archives, checksums,
packages, and the container image when the repository secrets and registries
are available.

## Snapshot release

Pushes to `main` or `develop` trigger the snapshot workflow. It builds
non-publishing artifacts for inspection.

```bash
make release-snapshot
```

## Runtime upgrade notes

The Core data model is one SQLite file. Any future schema change should remain
backward-compatible or include a clearly documented, tested upgrade path. Do
not reintroduce a migration service merely for routine startup initialization.
Always back up the data volume before a release that changes the schema.
