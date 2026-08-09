# SBOM & dependency-security policy

## Software Bill of Materials

A CycloneDX SBOM is generated for every release artifact:

```
syft dir:. -o cyclonedx-json=sbom.cdx.json
```

The SBOM enumerates all direct and transitive Go modules with versions and
licenses. It is produced in CI for release builds and attached to the release;
it is not committed to the repository (see `.gitignore`).

## Vulnerability scanning

Two gates run in CI on every push and pull request:

- `govulncheck ./...` — Go vulnerability database, call-graph aware.
- `gosec ./...` — static security analysis of the source.

A finding at or above the project's agreed severity threshold fails the build.

## Dependency hygiene

- `go.mod` pins a minimum Go version (1.25.x) and explicit dependency versions.
- `go mod tidy` is enforced in CI (`git diff --exit-code`) so the module graph
  cannot drift silently.
- New direct dependencies require review and must carry an OSI-approved license
  compatible with distribution; record notable ones in `NOTICE`.

## License compliance

Dependency licenses are captured in the SBOM. MPL-2.0 components (e.g. the MySQL
driver) are used unmodified as libraries; any local modification would require
publishing the affected source per MPL terms.
