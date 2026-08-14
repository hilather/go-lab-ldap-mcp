# LabLDAP first usable release notes

Date: 2026-08-14  
Tasks: T-120  
Images: `labldap-control:dev`, `labldap-bootstrap:dev` (OD-004; do not push)

## Versions

| Component | Pin |
| --- | --- |
| LabLDAP source | `git describe` / `git rev-parse` (see `dist/release/provenance.json`) |
| Go | 1.26 / toolchain `go1.26.5` |
| Node / pnpm | 22.14.0 / `pnpm@10.14.0` |
| React | 19.2.8 |
| 389 DS | `quay.io/389ds/dirsrv` digest in `deploy/docker/dirsrv.digest` (`389-ds-base-2.4.6`) |
| go-ldap | `v3.4.14` |
| OpenAPI | 3.0.3 subset; `api/openapi.yaml` |
| Config | `labldap.dev/v1alpha1` |

Build both application images with the same `VERSION` so
`labldap version` and `labldap-bootstrap version` match.

## Supported platforms

- **Advertised:** `linux/amd64`
- **Not advertised:** `linux/arm64` (upstream dirsrv digest includes it;
  no arm64 smoke in this environment). See
  [architectures.md](https://github.com/hilather/go-lab-ldap-mcp/blob/main/deploy/docker/architectures.md).
- Host: Docker Engine 24+, Compose v2.24+.

## Known limitations

- Active Directory emulation is out of scope.
- MCP transport is a package stub (see `docs/mcp/catalog.md`).
- Medium soak profile (~10k users / ~1k groups) is generated and
  compile-tested; live first-page numbers were not measured here
  (`docs/operations/limits.md`).
- Ephemeral tmpfs is not a forensic wipe (host swap).
- Management TLS `mode: generated` is a lab certificate, not public trust.
- Example secret files are `lab-fixture-*` placeholders.
- No public registry push (OD-004). No project LICENSE (OD-003).
- Signing (`cosign`) is optional and not performed.

## Migration guidance

This is the first packaged release. There is **no prior `apiVersion` to
migrate from**.

- Additive configuration stays `labldap.dev/v1alpha1`.
- Breaking configuration requires a new `apiVersion` and a documented
  operator step. Soft reset restores the data baseline; it is not a
  config migrator.
- Persistent volume: roll back image tags/digests together (control +
  bootstrap). `validate` reports drift. `make compose-reset` destroys
  `/data` and is not an upgrade tool.

## Acceptance

`make verify` is the release gate (format, lint, generate-drift, unit,
security, SBOM, checksums, archcheck). Product acceptance:

- REST + UI + direct LDAP on pinned Compose artifacts
  (`test/integration/compose`, `test/e2e`, `test/integration/dirsrv`).
- Ephemeral and persistent lifecycle tests
  (`TestEphemeralRecreateDropsRuntimeEntry`,
  `TestPersistentRestartKeepsRuntimeEntry`).
- MCP protocol acceptance is residual (catalog stub).

Security: three dated **approved** exceptions for the pinned `go1.26.5`
standard library (`GO-2026-6090`, `GO-2026-6089`, `GO-2026-5972`). See
`docs/security/dependency-policy.md`. No other criticals.
