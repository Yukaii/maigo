# Release process

Maigo uses GoReleaser v2 for tagged releases and snapshot artifacts. The
repository pins GoReleaser and the rest of the local toolchain in mise.toml.

## Local checks

~~~bash
make setup
make fmt-check
make lint
make test-unit
make check-goreleaser
~~~

The full integration suite additionally needs PostgreSQL; see docs/STATUS.md for
the isolated Compose database command.

Validate a release without publishing:

~~~bash
make release-dry
~~~

This creates local dist/ artifacts. Remove them with make clean if needed.

## Stable release

Stable releases are triggered by a v* tag. After the checks pass and the
working tree is committed:

~~~bash
git tag vX.Y.Z
git push origin vX.Y.Z
~~~

The release workflow runs GoReleaser, publishes GitHub release assets, and
publishes configured package/container artifacts. The workflow also supports
manual dispatch from GitHub Actions.

## Snapshot release

Pushes to main or develop trigger the snapshot workflow. It builds non-publishing
artifacts and uploads them to the workflow run for 30 days.

~~~bash
make release-snapshot
~~~

## Artifacts and versioning

GoReleaser builds Linux, macOS, and Windows binaries for amd64 and arm64 where
supported, plus checksums and archive metadata. Version, commit, and build date
are injected through the ldflags in .goreleaser.yaml.

The production-like local image is built with Dockerfile.production. The
GoReleaser container target currently uses the smaller scratch-based Dockerfile;
test the image entrypoint and database configuration separately before
publishing it.

## Troubleshooting

- Run make check-goreleaser to validate the configuration.
- A dirty tree can make release metadata surprising; commit intended changes
  before tagging.
- GoReleaser currently emits a deprecation warning for its dockers target;
  migrate to dockers_v2 when the project adopts that format.
- Publishing requires the workflow's GITHUB_TOKEN; Homebrew publishing is not
  configured in the current file.
