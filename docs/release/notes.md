# LabLDAP v0.4.0 release notes

Date: 2026-08-20  
Tag: **v0.4.0**  
Prior: [v0.3.0](https://github.com/hilather/go-lab-ldap-mcp/releases/tag/v0.3.0)  
Images: `labldap-control:dev`, `labldap-bootstrap:dev`, `labldapd:dev` (OD-004; do not push)

## Highlights since v0.3.0

- **Multi-domain managed suffixes.** Optional `spec.directory.additionalSuffixes`
  plus a structured entry API, tree browse in the console, and the same
  workflows on REST and MCP ([ADR-0011](https://github.com/hilather/go-lab-ldap-mcp/blob/v0.4.0/docs/adr/0011-multi-domain-managed-suffixes-and-structured-entries.md)).
  `apiVersion` stays `labldap.dev/v1alpha1`. No raw LDAP modify API.
- **Configurable management Host allow-list.** Extra hostnames via
  `spec.management.allowedHosts`, `LABLDAP_MANAGEMENT_ALLOWED_HOSTS`, or
  `--management-allowed-host` ([ADR-0010](https://github.com/hilather/go-lab-ldap-mcp/blob/v0.4.0/docs/adr/0010-management-http-allowed-hosts.md)).
  `*` is rejected.
- **Open the UI by IP.** Literal IP Host headers are accepted (DNS
  rebinding still rejects spoofed names). Compose still publishes
  loopback by default; set `LABLDAP_CONTROL_PUBLISH=0.0.0.0` to bind the
  management port on all host addresses.

## Versions

| Component | Pin |
| --- | --- |
| LabLDAP source | `v0.4.0` (`git describe`; see `dist/release/provenance.json`) |
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
  [architectures.md](https://github.com/hilather/go-lab-ldap-mcp/blob/v0.4.0/deploy/docker/architectures.md).
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
  Compose-generated certs use container addresses, so a LAN IP URL may
  also show a name mismatch; continue past the lab certificate.
- Example secret files are `lab-fixture-*` placeholders.
- No public registry push (OD-004). No project LICENSE (OD-003).
- Signing (`cosign`) is optional and not performed.

## Migration guidance

v0.3.0 → v0.4.0 is **additive**. `apiVersion` stays `labldap.dev/v1alpha1`.

1. Existing single-suffix scenarios keep working. `additionalSuffixes` is
   optional.
2. Extra management **hostnames** still need `allowedHosts` (or env/CLI).
   Literal IP Host headers no longer need that list.
3. To reach the UI at `https://<host-ip>:8443/`, set
   `LABLDAP_CONTROL_PUBLISH=0.0.0.0` and recreate the stack. LDAP/LDAPS
   publishes stay loopback.
4. Tokens, TLS files, ports, MCP flags, and password-policy YAML are
   unchanged.
5. Persistent volume: roll back image tags/digests together.

## Acceptance

`make verify` is the local release gate. CI heavy jobs run 389
integration and native integration. Product acceptance:

- REST account-workflow battery + host LDAP tools on both engines.
- Native engine unit/integration and `verify-native`.
- Playwright default remains the contract mock.
- Structured entry / tree UI path for additional suffixes.

Security: five dated **approved** exceptions for the pinned `go1.26.5`
standard library (`GO-2026-6090`, `GO-2026-6089`, `GO-2026-5972`,
`GO-2026-6218`, `GO-2026-5026`). See
[dependency-policy.md](https://github.com/hilather/go-lab-ldap-mcp/blob/v0.4.0/docs/security/dependency-policy.md).
No other criticals.
