# LabLDAP v0.3.0 release notes

Date: 2026-08-17  
Tag: **v0.3.0**  
Prior: [v0.2.2](https://github.com/hilather/go-lab-ldap-mcp/releases/tag/v0.2.2)  
Images: `labldap-control:dev`, `labldap-bootstrap:dev`, `labldapd:dev` (OD-004; do not push)

## Highlights since v0.2.2

- **Native is the default directory engine.** Omitted `spec.directory.engine`
  now compiles as `native` (`labldapd`). `make compose-up` starts the
  native stack. 389 Directory Server remains first-class:
  `engine: 389ds` and `make compose-up-389ds`.
- **Stay on `labldap.dev/v1alpha1`.** Dated ADR-0008 amendment records this
  one omitted-field reinterpretation; REST `/api/v1` and the compiler
  contract string are unchanged.
- **Fail-closed on mixed `/data`.** `labldapd` refuses to start if
  `--data-dir` looks like a 389 nsslapd tree or `labldapd.bolt` is not a
  bbolt file. Diagnostic names `compose-reset` / `engine: 389ds` and
  does not leak file contents.

## Versions

| Component | Pin |
| --- | --- |
| LabLDAP source | `v0.3.0` (`git describe`; see `dist/release/provenance.json`) |
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
  [architectures.md](https://github.com/hilather/go-lab-ldap-mcp/blob/v0.3.0/deploy/docker/architectures.md).
- Host: Docker Engine 24+, Compose v2.24+.

## Known limitations

- Active Directory emulation is out of scope.
- MCP is shipped (`POST /mcp`, `labldap mcp-stdio`). Mutation tools stay
  off unless `spec.management.mcp.register*` is true. Catalog:
  `docs/mcp/catalog.md`.
- Account-workflow expire/lock/unlock is REST and MCP in this release;
  the console UI for those actions is not yet wired (agent rule requires
  it for the next operator surface).
- Residual LabLDAP-surface deltas vs 389 remain in
  `docs/design/native-engine-parity-contract.md` and `test/parity`.
  389 is still the oracle.
- Medium soak profile (~10k users / ~1k groups) is generated and
  compile-tested; live first-page numbers were not measured here
  (`docs/operations/limits.md`).
- Ephemeral tmpfs is not a forensic wipe (host swap).
- Management TLS `mode: generated` is a lab certificate, not public trust.
- Example secret files are `lab-fixture-*` placeholders.
- No public registry push (OD-004). No project LICENSE (OD-003).
- Signing (`cosign`) is optional and not performed.

## Migration guidance

v0.2.2 → v0.3.0 is a **behavior change** for omitted `spec.directory.engine`.
`apiVersion` stays `labldap.dev/v1alpha1`.

1. If you already set `engine: native` or `engine: 389ds`, no default
   change applies.
2. If you omitted `engine` and run 389 today: add `engine: 389ds`
   **before** upgrading, or accept a new directory revision and a **hard
   reset** of `/data` (`make compose-reset`). On-disk formats are not
   portable between engines.
3. Do not point native `labldapd` at an existing 389 `/data` volume —
   the daemon refuses to start.
4. Tokens, TLS, ports, MCP flags, and password-policy YAML are unchanged.
5. Persistent volume: roll back image tags/digests together.

## Acceptance

`make verify` is the local release gate. CI heavy jobs run 389
integration and native integration. Product acceptance:

- REST account-workflow battery + host LDAP tools on both engines.
- Native engine unit/integration and `verify-native`.
- Playwright default remains the contract mock.

Security: five dated **approved** exceptions for the pinned `go1.26.5`
standard library (`GO-2026-6090`, `GO-2026-6089`, `GO-2026-5972`,
`GO-2026-6218`, `GO-2026-5026`). See
[dependency-policy.md](https://github.com/hilather/go-lab-ldap-mcp/blob/v0.3.0/docs/security/dependency-policy.md).
No other criticals.
