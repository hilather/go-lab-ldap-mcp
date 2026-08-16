# LabLDAP v0.2.0 release notes

Date: 2026-08-16  
Tag: **v0.2.0**  
Prior: [v0.1.0](https://github.com/hilather/go-lab-ldap-mcp/releases/tag/v0.1.0)  
Images: `labldap-control:dev`, `labldap-bootstrap:dev`, `labldapd:dev` (OD-004; do not push)

## Highlights since v0.1.0

- **Native engine (M9).** `labldapd` is an in-repo LDAPv3 engine with a
  bbolt store, ACI evaluation, password policy, memberOf, and Compose
  native profiles. 389 Directory Server remains the default. Select
  native with `spec.directory.engine: native`.
- **Dual-engine parity harness (T-147–T-150).** Native-lane verify,
  differential fuzz, soak/leak gates, and 389-as-oracle cases.
- **Account-workflow QA controls.** Named operations (not raw LDAP
  modify) on REST and MCP: expire password / must-change, clear expiry,
  lock / unlock, enable / disable, and account-state. `ldap_set_password`
  and `POST /api/v1/users/{id}/password` accept optional `mustChange`.
  Bind-test reports `must_change`.

Catalog: [docs/mcp/catalog.md](https://github.com/hilather/go-lab-ldap-mcp/blob/v0.2.0/docs/mcp/catalog.md).

## Versions

| Component | Pin |
| --- | --- |
| LabLDAP source | `v0.2.0` (`git describe`; see `dist/release/provenance.json`) |
| Go | 1.26 / toolchain `go1.26.5` |
| Node / pnpm | 22.14.0 / `pnpm@10.14.0` |
| React | 19.2.8 |
| 389 DS | `quay.io/389ds/dirsrv` digest in `deploy/docker/dirsrv.digest` (`389-ds-base-2.4.6`) |
| go-ldap | `v3.4.14` |
| OpenAPI | 3.0.3 subset; `api/openapi.yaml` |
| Config | `labldap.dev/v1alpha1` |

Build application images with the same `VERSION` so
`labldap version`, `labldap-bootstrap version`, and `labldapd version` match.

## Supported platforms

- **Advertised:** `linux/amd64`
- **Not advertised:** `linux/arm64` (upstream dirsrv digest includes it;
  no arm64 smoke in this environment). See
  [architectures.md](https://github.com/hilather/go-lab-ldap-mcp/blob/v0.2.0/deploy/docker/architectures.md).
- Host: Docker Engine 24+, Compose v2.24+.

## Known limitations

- Active Directory emulation is out of scope.
- MCP is shipped (`POST /mcp`, `labldap mcp-stdio`). Mutation tools stay
  off unless `spec.management.mcp.register*` is true. Catalog:
  `docs/mcp/catalog.md`.
- Medium soak profile (~10k users / ~1k groups) is generated and
  compile-tested; live first-page numbers were not measured here
  (`docs/operations/limits.md`).
- Ephemeral tmpfs is not a forensic wipe (host swap).
- Management TLS `mode: generated` is a lab certificate, not public trust.
- Example secret files are `lab-fixture-*` placeholders.
- No public registry push (OD-004). No project LICENSE (OD-003).
- Signing (`cosign`) is optional and not performed.

## Migration guidance

v0.1.0 → v0.2.0 is additive. `apiVersion` stays `labldap.dev/v1alpha1`.

- Omitted `spec.directory.engine` still means 389 DS.
- New REST paths and MCP tools do not rename existing operations.
- `PasswordBody.mustChange` is optional; existing set-password clients
  keep clearing must-change.
- Persistent volume: roll back image tags/digests together (control +
  bootstrap, and `labldapd` when using native). `validate` reports
  drift. `make compose-reset` destroys `/data` and is not an upgrade
  tool.

## Acceptance

`make verify` is the release gate (format, lint, generate-drift, unit,
security, SBOM, checksums, archcheck, native lane). Product acceptance:

- REST + UI + direct LDAP on pinned Compose artifacts
  (`test/integration/compose`, `test/e2e`, `test/integration/dirsrv`).
- Native engine unit/integration and `verify-native`.
- MCP catalog includes account-workflow tools; mutation tools stay
  behind `register*`. Playwright default remains the contract mock.

Security: five dated **approved** exceptions for the pinned `go1.26.5`
standard library (`GO-2026-6090`, `GO-2026-6089`, `GO-2026-5972`,
`GO-2026-6218`, `GO-2026-5026`). See
[dependency-policy.md](https://github.com/hilather/go-lab-ldap-mcp/blob/v0.2.0/docs/security/dependency-policy.md).
No other criticals.
