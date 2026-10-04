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
- No public registry push (OD-004). Project license is MIT (OD-003 resolved).
- Signing (`cosign`) is optional and not performed.

## Unreleased: stricter user attribute names

Pending the next tag (owner decision on whether this needs an `apiVersion`
bump). User attribute writes from REST, MCP, the console and scenario YAML
now share one rule: `objectClass`, numeric OIDs, protected names in any
spelling, and option or alias spellings of `uid`/`cn`/`sn` (`cn;lang-en`,
`commonName`, `surname`, `userid`) are rejected, and names that address
the same attribute (`mail`/`Mail`, `ou`/`organizationalUnitName`) are a
`duplicate_attribute` error. A scenario that used these spellings in
`users[].attributes` compiled before (the seed dropped them) and now fails
to compile until they are removed. The user view no longer carries
optioned `cn`/`sn`/`uid` values, so a user that has them gets a new
revision after upgrading, and later edits to those values through the
entry API do not change the user revision.

## Unreleased: filter attribute descriptions (native engine)

Native search filters now treat attribute descriptions as 389 does
(contract C6): `(description=hello)` matches a value stored as
`description;lang-en`, `(userid=x)` and numeric OIDs such as
`(2.5.4.0=inetOrgPerson)` resolve to their type, and an OID or second
descriptor with options (`userid;x-test`) matches nothing. Compare is
unchanged (delta D34). The bbolt equality index now keys postings by
attribute type (index format 3): the first start after upgrading rebuilds
the DN and equality indexes once, inside the open transaction, and stamps
the format so later starts do not rebuild (earlier builds rebuilt on every
start after a format change because the stamp was never written).
Downgrade caveat: an older binary rebuilds on every start of a format-3
store and never rewrites the stamp, so after a
downgrade-then-upgrade round trip this binary sees format 3 and does not
rebuild, and indexed searches can miss subtype values written by the older
binary. Recover with a reset or a fresh store volume (there is no rebuild
command).

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

`make verify` is the local release gate. With Docker it also runs 389
integration, dual-engine parity and the isolated live browser smoke
(`make test-e2e-live`, which needs host `ldapsearch`, Compose 2.24.4+ and
free ports 18443/13636). CI heavy jobs run 389 integration, native
integration, the live browser smoke (`e2e-live`), and `native-checks` with
the 389 differential oracle required (`LABLDAP_REQUIRE_389=1`). A local
`make verify` still skips that oracle with a message when the pinned 389
image is not present; set `LABLDAP_REQUIRE_389=1` to pull and require it.
Product acceptance:

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
