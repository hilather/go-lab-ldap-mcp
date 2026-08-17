# LabLDAP v0.2.2 release notes

Date: 2026-08-16  
Tag: **v0.2.2**  
Prior: [v0.2.1](https://github.com/hilather/go-lab-ldap-mcp/releases/tag/v0.2.1)  
Images: `labldap-control:dev`, `labldap-bootstrap:dev`, `labldapd:dev` (OD-004; do not push)

## Highlights since v0.2.1

- **Native CI python ldap3.** The independent ldap3 client no longer
  requests 389-only `entryDN` (parity D6) or downloads schema
  (`get_info=ALL`), which made `TestCompatibilityLDAPClients/python_ldap3`
  fail under `make test-integration-native`. It searches `uid`. Native CI
  also installs `python3-venv`.

## Highlights since v0.2.0

- **Dual-engine REST→LDAP workflow IT.** `TestRESTAccountWorkflowLDAPTools`
  toggles enable/lock/expire/password via REST and checks the same user
  with host `ldapwhoami` / `ldapsearch` on 389 and native.
- **CI runs both engines when it matters.** `make test-integration` (389)
  still runs on heavy (non-docs) changes. `make test-integration-native`
  runs only when native LDAP paths change (`internal/ldapserver`,
  `cmd/labldapd`, `internal/directory/native`, dual-engine IT/parity,
  native compose/image).
- **Agent rules.** New operator REST/MCP actions must be usable in the
  UI. New native directory behavior that 389 also implements must have a
  parametrized integration test on both engines.
- **Bind-test / set-password.** Bind-test reports `locked` and
  `must_change` from directory stamps even when 389 simple bind still
  succeeds. Set-password stamp cleanup ignores missing attributes after
  the password replace.

Catalog: [docs/mcp/catalog.md](https://github.com/hilather/go-lab-ldap-mcp/blob/v0.2.2/docs/mcp/catalog.md).

## Versions

| Component | Pin |
| --- | --- |
| LabLDAP source | `v0.2.2` (`git describe`; see `dist/release/provenance.json`) |
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
  [architectures.md](https://github.com/hilather/go-lab-ldap-mcp/blob/v0.2.2/deploy/docker/architectures.md).
- Host: Docker Engine 24+, Compose v2.24+.

## Known limitations

- Active Directory emulation is out of scope.
- MCP is shipped (`POST /mcp`, `labldap mcp-stdio`). Mutation tools stay
  off unless `spec.management.mcp.register*` is true. Catalog:
  `docs/mcp/catalog.md`.
- Account-workflow expire/lock/unlock is REST and MCP in this release;
  the console UI for those actions is not yet wired (agent rule requires
  it for the next operator surface).
- Medium soak profile (~10k users / ~1k groups) is generated and
  compile-tested; live first-page numbers were not measured here
  (`docs/operations/limits.md`).
- Ephemeral tmpfs is not a forensic wipe (host swap).
- Management TLS `mode: generated` is a lab certificate, not public trust.
- Example secret files are `lab-fixture-*` placeholders.
- No public registry push (OD-004). No project LICENSE (OD-003).
- Signing (`cosign`) is optional and not performed.

## Migration guidance

v0.2.1 → v0.2.2 is additive. `apiVersion` stays `labldap.dev/v1alpha1`.

- Bind-test `outcome` may now be `locked` or `must_change` when those
  stamps are present even if a raw LDAP bind still succeeds on 389.
- Omitted `spec.directory.engine` still means 389 DS.
- Persistent volume: roll back image tags/digests together.

## Acceptance

`make verify` is the local release gate. CI heavy jobs run 389
integration and native integration. Product acceptance:

- REST account-workflow battery + host LDAP tools on both engines.
- Native engine unit/integration and `verify-native`.
- Playwright default remains the contract mock.

Security: five dated **approved** exceptions for the pinned `go1.26.5`
standard library (`GO-2026-6090`, `GO-2026-6089`, `GO-2026-5972`,
`GO-2026-6218`, `GO-2026-5026`). See
[dependency-policy.md](https://github.com/hilather/go-lab-ldap-mcp/blob/v0.2.2/docs/security/dependency-policy.md).
No other criticals.
