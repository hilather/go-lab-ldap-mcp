# LabLDAP v0.4.1 release notes

Date: 2026-08-23  
Tag: **v0.4.1**  
Prior: [v0.4.0](https://github.com/hilather/go-lab-ldap-mcp/releases/tag/v0.4.0)  
Images: `labldap-control:dev`, `labldap-bootstrap:dev`, `labldapd:dev` (OD-004; do not push)

## Highlights since v0.4.0

- **Additive TLS SANs on `setuptls generate`.** Repeatable `--dns` / `--ip`
  (directory) and `--management-dns` / `--management-ip` (management) flags
  include a public hostname or address without replacing the directory
  CN/SAN. `--host` stays `directory`. Address literals must use `--ip`
  so they land in `IPAddresses`, not `DNSNames`. Extra SANs apply on first
  mint or `--force`; skip-if-exists is all-or-nothing.

v0.4.0 highlights still apply: multi-domain managed suffixes
([ADR-0011](https://github.com/hilather/go-lab-ldap-mcp/blob/v0.4.1/docs/adr/0011-multi-domain-managed-suffixes-and-structured-entries.md)),
configurable management Host allow-list
([ADR-0010](https://github.com/hilather/go-lab-ldap-mcp/blob/v0.4.1/docs/adr/0010-management-http-allowed-hosts.md)),
and UI access by literal IP.

## Versions

| Component | Pin |
| --- | --- |
| LabLDAP source | `v0.4.1` (`git describe`; see `dist/release/provenance.json`) |
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
  [architectures.md](https://github.com/hilather/go-lab-ldap-mcp/blob/v0.4.1/deploy/docker/architectures.md).
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
  Compose-generated certs still use container addresses. Host-side
  `setuptls generate --dns` / `--ip` (and the management equivalents)
  can add a public name or LAN IP SAN; extra SANs are not the same as
  `allowedHosts`.
- Example secret files are `lab-fixture-*` placeholders.
- No public registry push (OD-004). No project LICENSE (OD-003).
- Signing (`cosign`) is optional and not performed.

## Migration guidance

v0.4.0 → v0.4.1 is **additive**. `apiVersion` stays `labldap.dev/v1alpha1`.

1. Default `make compose-up` / `setup-tls` is unchanged (`--host directory`).
2. To include a public hostname or address on the lab leaf, pass `--dns`
   and/or `--ip` (and `--management` plus `--management-dns` /
   `--management-ip` for the optional management cert). Do not pass an
   IP as `--host` or `--dns`.
3. Existing PEMs are not updated. Re-mint with `--force` to pick up extra
   SANs (this rotates the lab CA and leaves).
4. Extra certificate SANs do not change the management HTTP Host
   allow-list. Extra **hostnames** still need `allowedHosts` (or env/CLI).
5. Tokens, TLS file layout, ports, MCP flags, and password-policy YAML
   are unchanged.
6. Persistent volume: roll back image tags/digests together.

## Acceptance

`make verify` is the local release gate. CI heavy jobs run 389
integration and native integration. Product acceptance:

- REST account-workflow battery + host LDAP tools on both engines.
- Native engine unit/integration and `verify-native`.
- Playwright default remains the contract mock.
- Structured entry / tree UI path for additional suffixes.
- `setuptls generate` extra-SAN unit tests (IP vs DNS, merge, skip-if-exists).

Security: five dated **approved** exceptions for the pinned `go1.26.5`
standard library (`GO-2026-6090`, `GO-2026-6089`, `GO-2026-5972`,
`GO-2026-6218`, `GO-2026-5026`). See
[dependency-policy.md](https://github.com/hilather/go-lab-ldap-mcp/blob/v0.4.1/docs/security/dependency-policy.md).
No other criticals.
