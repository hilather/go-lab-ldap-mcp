# LabLDAP v0.7.0 release notes

Date: 2026-10-05  
Tag: **v0.7.0** (on the squash commit of the v0.7.0 notes PR)  
Prior: [v0.6.0](https://github.com/hilather/go-lab-ldap-mcp/releases/tag/v0.6.0)  
Images: `labldap-control:dev`, `labldap-bootstrap:dev`, `labldapd:dev` (OD-004; do not push)

v0.7.0 contains everything merged after v0.6.0, which is [#33](https://github.com/hilather/go-lab-ldap-mcp/pull/33). Native now
matches the pinned 389 image for cross-parent moves (`moddn`, CAND-39) and case-only
renames (CAND-30), and the runtime ACIs grant `moddn`, so REST, MCP and the console
can move entries on both engines. The owner decided this on 2026-10-04 (contract C8;
oracle probes 30–34). It is a minor release because every scenario gets a new
directory revision; read the upgrade risks first. Earlier releases are summarized at
the end.

## Unreleased (after v0.7.0)

- Go toolchain and builder image move from `go1.26.8` to `go1.26.9` (`go.mod`
  `toolchain`, CI/Makefile `GOTOOLCHAIN`, `deploy/docker/golang.digest` and the
  Dockerfiles). go1.26.8 lacks the standard-library fixes for GO-2026-6603..6617.

## Upgrade risks (read first)

These apply to every deployment, including the default lab profile, because the
runtime ACI text changes.

1. **New directory revision on both engines.** The runtime ACIs
   `runtime-people-write`, `runtime-groups-write` and `runtime-addsuffix-N-write` now
   include `moddn`. Runtime ACIs feed the directory revision, so **every scenario gets
   a new directory revision on both engines**. `/health/ready` is 503 until a
   write-mode bootstrap writes the new marker and ACIs. Persistent deployments with
   `startupMode: validate` need one merge apply. Until then `verify`/`inspect` report
   a mismatch and `reset.Compare` fails.
2. **Native and 389 change at different times.** Native evaluates the ACIs it
   compiles at labldapd start, so native moves follow the new rules as soon as the
   upgraded labldapd runs. 389 runtime moves stay 50 until the bootstrap rewrites the
   stored ACIs.
3. **Versions must match** (see Versions). An old labldapd with a new control plane is
   not detected, because labldapd publishes no revision, and it keeps refusing runtime
   moves with 50. Raw ACIs that use `moddn` stop an old labldapd with `invalid_aci`.
4. **Rollback.** A rollback to v0.6.0 leaves 389 ACIs carrying `moddn`, so `verify`
   reports a mismatch until a bootstrap rewrites them. Moves made in the meantime
   stay.
5. **Raw ACIs and DSL ACLs on native.** Raw ACIs on native that relied on write + add
   for moves must grant `moddn` on the destination. Operator DSL ACLs no longer allow
   moves on native, because the DSL `permissions` list cannot express `moddn`. This
   matches 389.
6. **Cross-suffix moves and result codes.** Moves between managed suffixes are
   refused with affectsMultipleDSAs(71) on both engines (native used to allow them),
   and REST/MCP refuse them up front with a `newDN` / `forbidden` field error. A
   missing modrdn source or new superior is 32 for Directory Manager (even without
   `moddn`) and for a subject holding `moddn` there, else 50. Case-only renames now
   succeed on native instead of returning 68.
7. **Security.** The runtime credential can now move entries under people and groups
   over raw LDAP on both engines, including a whole subtree. That includes
   `ou=groups` under `ou=people`, and the credential's own entry out of people (which
   would cut off its ACIs until a reset). REST and MCP refuse moves of protected
   entries (suffix roots, people, groups, the runtime account and the marker), but not
   of an OU that contains one of them. A user moved out of people leaves the Users
   list and the `runtime-password` scope; a group moved out of groups leaves the
   Groups list. `target_from`/`target_to` are not supported on native (D38).

`apiVersion` stays `labldap.dev/v1alpha1`. The owner question left open in v0.6.0,
whether the stricter user attribute names ([#27](https://github.com/hilather/go-lab-ldap-mcp/pull/27),
[#18](https://github.com/hilather/go-lab-ldap-mcp/pull/18)) need an `apiVersion` bump, is still open; #33 does not
change it. REST and MCP shapes are unchanged; only
the `ldap_move_entry` / move description text now says the new DN must stay under
the same managed suffix as the entry.

## Highlights since v0.6.0

- Native implements 389's `moddn` permission for moves, and the runtime ACIs grant it,
  so moves within and between people and groups (and within each additional suffix)
  work through REST, MCP and the console on both engines ([#33](https://github.com/hilather/go-lab-ldap-mcp/pull/33); CAND-39
  resolved).
- Case-only renames (`uid=keeper` → `uid=Keeper`) respell the DN on native as on 389
  ([#33](https://github.com/hilather/go-lab-ldap-mcp/pull/33); CAND-30 resolved; only its internal-spaces half is split off, into CAND-40,
  still open).
- Moves between managed suffixes are refused with 71 on both engines and up front on
  REST/MCP ([#33](https://github.com/hilather/go-lab-ldap-mcp/pull/33)).
- ADR-0011 items 7 and 8 are amended for `moddn` and same-suffix moves; delta D37 is
  documented ([#33](https://github.com/hilather/go-lab-ldap-mcp/pull/33)).

## Details: moves (moddn) and case-only renames ([#33](https://github.com/hilather/go-lab-ldap-mcp/pull/33))

Native now matches the pinned 389 image for cross-parent moves and case-only renames
(contract C8; oracle probes 30–34; CAND-39 and CAND-30 resolved by the owner decision
of 2026-10-04 to add `moddn` and grant it in the runtime ACIs).

- **Moves to a different parent work on both engines (`moddn`).** Native
  now supports 389's `moddn` permission: a move needs `moddn` on the new
  superior (entry level) plus write on the new RDN attribute on the old DN
  and, when `deleteoldrdn` is set, write on the old RDN attribute too; no
  add or delete right is checked any more. The runtime ACIs
  `runtime-people-write`, `runtime-groups-write` and
  `runtime-addsuffix-N-write` now include `moddn`, so REST, MCP and the
  console can move entries within and between people and groups (and
  within each additional suffix) on both engines; before, 389 refused every
  such move with 50. Subtree moves carry their children, member values
  pointing into the moved subtree follow it and memberOf is recomputed. A
  missing new superior is 32 for a caller holding `moddn` there, else 50.
- **Moves between managed suffixes are refused.** The LDAP answer is
  affectsMultipleDSAs(71) on both engines (389 keeps each suffix in its
  own backend; native used to allow the move). REST and MCP refuse it up
  front with a `newDN` / `forbidden` field error ("moves across managed
  suffixes are not supported") once an If-Match revision is present and
  before it is compared, so a stale revision on such a move still gets the
  403; on 389 this used to be a misleading "directory unavailable" error
  from the 71.
- **Case-only renames succeed (`uid=keeper` -> `uid=Keeper`).** Native
  used to answer 68; it now respells the DN (and its children's DNs), as
  on 389. With deleteoldrdn the RDN value is respelled too. Member values
  and memberOf are left as written. A rename takes its parent spelling
  from the request DN (an explicit equal newSuperior is ignored) and a
  move takes the stored spelling of the new parent; a rename whose result
  only changes the parent spelling respells it instead of being a no-op.
- **Operator DSL ACLs no longer allow moves on native.** They needed
  write and add before; a move now needs `moddn`, which the DSL
  `permissions` list cannot express (raw ACIs can). This matches 389,
  which never allowed DSL-granted moves.
- **Missing modrdn source or superior: 32 with `moddn`, else 50.** A
  subject other than Directory Manager gets 32 for a missing source entry
  or new superior only if it holds `moddn` on that DN through an ACI whose
  `targetattr` covers an arbitrary attribute; otherwise 50 (refines the
  v0.6.0 CAND-36 rule, which answered 50 for every such subject).
- **`targetattr!="*"` ACIs and moves.** A negated list holding `"*"`
  still covers no attribute, but when it lists `moddn` it does grant the
  entry-level move gate on the new superior.

## Versions

| Component | Pin |
| --- | --- |
| LabLDAP source | `v0.7.0` (`git describe`; see `dist/release/provenance.json`) |
| Go | 1.26 / toolchain `go1.26.8` |
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
  [architectures.md](https://github.com/hilather/go-lab-ldap-mcp/blob/main/deploy/docker/architectures.md).
- Host: Docker Engine 24+, Compose v2.24+.

## Known limitations

- Active Directory emulation is out of scope.
- MCP is shipped (`POST /mcp`, `labldap mcp-stdio`). Mutation tools stay
  off unless `spec.management.mcp.register*` is true. Catalog:
  `docs/mcp/catalog.md`.
- Residual LabLDAP-surface deltas vs 389 remain in
  `docs/design/native-engine-parity-contract.md` and `test/parity`.
  389 is still the oracle.
- ~~Cross-parent moves differ (CAND-39)~~ and ~~case-only renames return 68 on
  native (CAND-30)~~: resolved in v0.7.0 (see "Details" above). Moves need `moddn`
  on the new superior on both engines, the runtime ACIs grant it, and case-only
  renames respell the DN.
- Moves between managed suffixes are refused (71 over LDAP, `newDN` / `forbidden`
  on REST and MCP) on both engines; each suffix is its own 389 backend.
- Operator DSL ACLs cannot grant moves: the DSL `permissions` list has no `moddn`
  (raw ACIs can). A DSL `moddn` permission is a possible follow-up.
- 389 keeps the attribute-type case of the RDN in a new DN, while native lowercases
  it (documented delta D37).
- `target_from` / `target_to` ACI keywords are rejected on native (D38).
- A ModifyDN request that spells the suffix value in a different case
  (`uid=keeper,ou=src,DC=EXAMPLE,dc=test`) is refused with 53 on native, while 389
  accepts it and stores that spelling: native's suffix check compares RDNs exactly
  (CAND-40, pending a fold-aware fix).
- Native Bind does not yet complete or abandon outstanding operations first
  (proposed ADR-0014).
- Directory writes are serialized within one control process; external LDAP writers
  and other control processes keep the documented residual race on engines without
  assertion controls.
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

## Migration guidance

v0.6.0 → v0.7.0 keeps `apiVersion: labldap.dev/v1alpha1`; REST, MCP and config
shapes are unchanged. Read "Upgrade risks" first.

1. Upgrade labldapd, the control plane and the bootstrap image together with the same
   `VERSION`. An old labldapd with a new control plane is not detected.
2. Run one write-mode bootstrap (default `make compose-up` does this) so the runtime
   ACIs gain `moddn` and the new marker is written; `/health/ready` is 503 until then.
   Persistent deployments with `startupMode: validate` need one merge apply.
3. Raw ACIs (`allowRawACI: true`) on native that granted moves through write + add
   must grant `moddn` on the destination (entry level, on the new superior).
4. DSL ACLs cannot grant moves; use a raw ACI with `moddn` if an operator account
   needs to move entries.
5. Clients that moved entries between managed suffixes on native must stop: those
   moves now fail with 71 (LDAP) or a `newDN` / `forbidden` field error (REST/MCP).
6. Rollback to v0.6.0: roll back image tags together, then run a write-mode bootstrap
   so the stored 389 ACIs drop `moddn`.
7. Tokens, TLS file layout, ports, MCP flags and password-policy YAML are unchanged.
8. Upgrading from v0.5.0 or earlier: first apply the v0.6.0 migration guidance and
   upgrade risks in the
   [v0.6.0 notes](https://github.com/hilather/go-lab-ldap-mcp/blob/v0.6.0/docs/release/notes.md)
   (all ten risks, including the raw ACI `targetattr` schema check and `||` lists,
   DSL attribute lists, index formats 2 and 3, TLS re-mint, revision tokens and
   absolute filters).

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
- Dual-engine parity for the moves, missing source/superior and case-only rename rows,
  replaying oracle probes 30–34 against the pinned 389 image with `nsslapd-moddn-aci`
  on ([#33](https://github.com/hilather/go-lab-ldap-mcp/pull/33)); dual-engine integration `TestModDNMatchesOracle` and the
  multi-domain `TestRESTMovesWithRuntimeGrant` (the cross-suffix 71 row lives only
  there, because `test/parity` has no additional-suffix fixture).
- The live browser smoke (native) moves an entry from people to groups and respells it
  ([#33](https://github.com/hilather/go-lab-ldap-mcp/pull/33)).

Security: the toolchain is still `go1.26.8` (unchanged from v0.6.0); there are no approved
exceptions. See
[dependency-policy.md](https://github.com/hilather/go-lab-ldap-mcp/blob/main/docs/security/dependency-policy.md).

## Earlier releases

### v0.6.0 (2026-10-04)

Tag `v0.6.0` at `175afc7`; prior v0.5.0. Changes: [#14](https://github.com/hilather/go-lab-ldap-mcp/pull/14)–[#32](https://github.com/hilather/go-lab-ldap-mcp/pull/32).
Full notes, including the ten upgrade risks and per-PR details:
[docs/release/notes.md at v0.6.0](https://github.com/hilather/go-lab-ldap-mcp/blob/v0.6.0/docs/release/notes.md).

- **Security and correctness** from the 2026-10-03 review series: directory policy and
  reset isolation, native LDAP authorization and rename safety, serialized directory
  mutations, and native `userPassword` hashing under option spellings
  ([#18](https://github.com/hilather/go-lab-ldap-mcp/pull/18), [#19](https://github.com/hilather/go-lab-ldap-mcp/pull/19), [#22](https://github.com/hilather/go-lab-ldap-mcp/pull/22), [#25](https://github.com/hilather/go-lab-ldap-mcp/pull/25)).
- **Native parity with the pinned 389 image:** user attribute names and aliases,
  filter attribute descriptions, ACI `targetattr` schema checks, same-parent ModRDN
  gates, absolute filters, and DSL attribute lists compiled to 389 lists
  ([#27](https://github.com/hilather/go-lab-ldap-mcp/pull/27)–[#29](https://github.com/hilather/go-lab-ldap-mcp/pull/29), [#31](https://github.com/hilather/go-lab-ldap-mcp/pull/31)).
- **Console:** account and structured-entry workflows ([#20](https://github.com/hilather/go-lab-ldap-mcp/pull/20)).
- **TLS, release and build:** `setuptls` leaves carry Authority Key Identifier,
  stricter release gates, toolchain `go1.26.8`, MIT `LICENSE`
  ([#14](https://github.com/hilather/go-lab-ldap-mcp/pull/14)–[#17](https://github.com/hilather/go-lab-ldap-mcp/pull/17), [#21](https://github.com/hilather/go-lab-ldap-mcp/pull/21)).

Its upgrade risks were: unknown ACL/ACI attribute names fail startup; an ACI without
`targetattr` no longer covers attributes; single-`|` raw ACI lists stop labldapd;
stricter user attribute names; filter matching and index format 3; persistent store
index format 2; generated TLS leaves need re-minting; cached revision tokens rotate;
DSL attribute lists compile to real 389 lists; absolute filters and ModRDN result
codes. `apiVersion` stayed `labldap.dev/v1alpha1`, with the `apiVersion`-bump question for
the stricter user attribute names left open for the owner.

### v0.5.0 (2026-08-29)

Tag `v0.5.0` at `f6b68ce`; prior v0.4.1. Changes: [#10](https://github.com/hilather/go-lab-ldap-mcp/pull/10), [#12](https://github.com/hilather/go-lab-ldap-mcp/pull/12), [#13](https://github.com/hilather/go-lab-ldap-mcp/pull/13).

- **`setuptls generate` fails closed on address and management mistakes.** `--host`
  rejects IP literals like `--dns` does (use `--ip`), and `--management-dns` /
  `--management-ip` without `--management` now exit with an error before writing any
  PEMs instead of silently dropping the management certificate ([#10](https://github.com/hilather/go-lab-ldap-mcp/pull/10)).
- **Bracketed IPv6** (`[::1]`) is treated as an address: `--host` / `--dns` reject it
  and `--ip '[::1]'` mints an IP SAN ([#12](https://github.com/hilather/go-lab-ldap-mcp/pull/12)).
- **Dark Directory workspace.** `/tree` is a split DIT and inspector, and login plus
  the other operator page bodies use the same dark chrome with self-hosted IBM Plex
  (CSP `font-src 'self'`). Routes and behavior are unchanged ([#13](https://github.com/hilather/go-lab-ldap-mcp/pull/13)).

No configuration, REST or MCP contract changed; `apiVersion` stayed
`labldap.dev/v1alpha1`. At that tag the pinned toolchain was still `go1.26.5`
with the five dated standard-library exceptions.

### v0.4.1 (2026-08-23)

- **Additive TLS SANs on `setuptls generate`.** Repeatable `--dns` / `--ip`
  (directory) and `--management-dns` / `--management-ip` (management) flags
  include a public hostname or address without replacing the directory
  CN/SAN. `--host` stays `directory`. Address literals must use `--ip`
  so they land in `IPAddresses`, not `DNSNames`. Extra SANs apply on first
  mint or `--force`; skip-if-exists is all-or-nothing.

v0.4.0 highlights still applied: multi-domain managed suffixes
([ADR-0011](https://github.com/hilather/go-lab-ldap-mcp/blob/v0.4.1/docs/adr/0011-multi-domain-managed-suffixes-and-structured-entries.md)),
configurable management Host allow-list
([ADR-0010](https://github.com/hilather/go-lab-ldap-mcp/blob/v0.4.1/docs/adr/0010-management-http-allowed-hosts.md)),
and UI access by literal IP.
