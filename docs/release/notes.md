# LabLDAP v0.6.0 release notes

Date: 2026-10-04  
Tag: **v0.6.0** (`main` at `db0bee4`)  
Prior: [v0.5.0](https://github.com/hilather/go-lab-ldap-mcp/releases/tag/v0.5.0)  
Images: `labldap-control:dev`, `labldap-bootstrap:dev`, `labldapd:dev` (OD-004; do not push)

v0.6.0 contains everything merged after v0.5.0 ([#14](https://github.com/hilather/go-lab-ldap-mcp/pull/14)–[#29](https://github.com/hilather/go-lab-ldap-mcp/pull/29)): security and
correctness fixes from the 2026-10-03 review series, complete console account and entry
workflows, stricter release gates, and native-engine attribute, filter and ACI
behavior aligned with the pinned 389 image. Earlier releases are summarized at the end.

## Unreleased (after v0.6.0): modrdn gates, star lists, absolute filters and DSL attribute lists

Not in v0.6.0; for the next release. Native now matches
the pinned 389 image in four more places (contract C8; oracle probes
25-29; CAND-36, CAND-37, CAND-38 and the DSL list follow-up resolved):

- **ModRDN (same-parent rename) uses 389's gates.** The subject needs
  write on the new RDN attribute on the old DN (and on the old RDN
  attribute with deleteoldrdn); only a deny-write ACI without
  `targetattr` blocks at entry level, and no add right is needed. A
  rename is no longer blocked by an unrelated attribute-scoped deny such
  as `deny (write) targetattr="description;lang-en"`.
- **ModRDN result codes follow 389.** A subject other than Directory
  Manager now gets 50 instead of 32 for a missing source entry. A rename
  onto an existing DN (68) and a move beneath itself (53) are answered
  before any access check, so these codes now tell a subject without
  rights that the entry exists, as on 389. Renaming an entry to its own
  DN now succeeds (it was 68) and only updates `modifyTimestamp` and
  `modifiersName`.
- **Absolute filters are rejected.** A search whose filter holds `(&)` or
  `(|)` anywhere (RFC 4526) now fails with protocolError(2) "Bad search
  filter" for every subject and base, before controls are checked; the
  connection stays open. Clients that used `(&)` as "match everything"
  must use `(objectClass=*)`.
- **`targetattr!="*"` loads.** `"*"` is accepted in `targetattr` lists
  and after `!=`. A negated list holding `"*"` covers no attribute (the
  ACI then applies only to add, delete and the modrdn entry gate); a
  positive one covers every attribute. Raw ACIs that stopped labldapd
  with `invalid_aci` now load.
- **DSL attribute lists compile to one 389 list.** `attributes.allow:
  [uid, sn]` now emits `targetattr="uid || sn"` instead of
  `targetattr="*"` (the v0.6.0 over-grant listed under Known limitations is fixed), `attributes.deny`
  with no allow list emits `targetattr!="a || b"`, and both lists emit
  the allow names that no deny name covers. New validation errors on
  `spec.acls.<id>.attributes.deny`: `invalid_attribute_filter` for a deny
  name with options narrower than a same-attribute allow name, for a
  combination that leaves no attribute, and for `deny: ["*"]` (it used to
  compile; remove the ACL or narrow it). More than 64 names in one list
  fail with `too_many_attributes`. A deny name with an empty option
  (`"mail;"`) covers nothing and does not narrow the allow list.
- **REST, MCP and the console reject absolute filters up front.** A
  search filter holding `(&)` or `(|)` is a `filter` / `invalid` field
  error ("use (objectClass=*)") instead of an engine protocolError shown
  as "directory unavailable" (this also fixes the 389 engine).

Upgrade risk: DSL ACLs with more than one attribute name now grant
**less** than before (only the listed attributes). The compiled
directory revision changes for such scenarios, so the first write-mode
bootstrap rewrites their ACIs; until then `verify`/`inspect` report a
mismatch and `reset.Compare` fails, on both engines. Renames under an
attribute-scoped deny now succeed where native refused them, and
existence of rename targets is disclosed by 68/53 as on 389. Cross-parent
moves are unchanged: native still allows them with entry write and add,
while 389 refuses them for every account without a `moddn` grant,
including the runtime account (open CAND-39, owner decision pending).
Case-only renames still return 68 on native (open CAND-30).

## Upgrade risks (read first)

Risks 1–4 affect deployments that use raw ACIs (`allowRawACI: true` with `aciTexts`)
on the native engine, or that rely on the older attribute spellings. Risks 5–8 can
also hit the default lab and any other deployment: 5 and 6 apply to every persistent
native store (`storageMode: persistent`, for example `make compose-up-persistent`);
7 applies to any TLS files minted by an earlier `setuptls`, including the default
lab's `make compose-up`, whose `setup-tls` step keeps existing PEMs; 8 applies to
every client that holds cached user/account revisions. **The default lab
profile is not affected by risks 1 and 2:** `deploy/compose/scenario*.yaml` and
`config/examples/example-lab.yaml` set `allowRawACI: false` and use one DSL ACL with
explicit attributes (`attributes.allow: ["*"]`, `deny: [userPassword]`), which the
compiler always emits with an explicit, schema-known `targetattr`.

1. **Unknown attribute names in ACLs and ACIs now fail startup** ([#29](https://github.com/hilather/go-lab-ldap-mcp/pull/29)). A
   `targetattr` name must exist in the pinned 389 schema (type, alias, numeric OID or
   `-oid` placeholder). A raw ACI naming anything else (a typo, an object class such as
   `person`, the native-only `pwdChangedTime`) stops labldapd with `aciTexts` /
   `invalid_aci`. A DSL ACL naming one in `attributes.allow` or `attributes.deny` fails
   `labldap` config validation with `unknown_attribute`, and every element of the list
   is now checked.
2. **An ACI with no `targetattr` no longer grants or denies attribute access**, matching
   389 ([#29](https://github.com/hilather/go-lab-ldap-mcp/pull/29)). It now applies only to add, delete and the modrdn entry gates. A deny
   ACI without `targetattr` stops denying attribute reads and writes (wider access); an
   allow ACI without `targetattr` stops granting them (narrower access). Add
   `(targetattr="*")` to keep the old meaning. In the same change, option-bearing names
   (`uid;x-test`) cover only those descriptions, and attribute-scoped `deny (search)` /
   `deny (write)` no longer hide or lock whole entries.
3. **Raw ACI list syntax** ([#28](https://github.com/hilather/go-lab-ldap-mcp/pull/28)). A `targetattr` list separated by a single `|`
   (`"cn|sn"`) now stops labldapd at startup; rewrite it as `"cn || sn"`. Numeric-OID
   names are accepted and compared literally (a deny on `2.5.4.35` does not deny
   `userPassword`); native logs a startup warning for each one.
4. **Stricter user attribute names and new aliases** ([#27](https://github.com/hilather/go-lab-ldap-mcp/pull/27), following [#18](https://github.com/hilather/go-lab-ldap-mcp/pull/18)).
   `rfc822Mailbox` resolves to `mail` and `gn` to `givenName`. User writes and scenario
   YAML reject `objectClass`, numeric OIDs, protected names in any spelling, and
   option or alias spellings of `uid`/`cn`/`sn`; two names for one attribute are
   `duplicate_attribute`. A scenario that used these spellings in `users[].attributes`
   now fails to compile until they are removed.
5. **Filter matching and the index format** ([#28](https://github.com/hilather/go-lab-ldap-mcp/pull/28)). Native filters match attribute
   options, subtypes, second descriptors and numeric OIDs as 389 does. The bbolt
   equality index moves to format 3; the first start rebuilds the DN and equality
   indexes once and now stamps the format version, so later starts do not rebuild (the
   stamp was never written before). Downgrading to an older binary and back can leave
   indexed searches missing values; recover with a reset or a fresh store volume.
6. **Persistent native stores** ([#19](https://github.com/hilather/go-lab-ldap-mcp/pull/19)). Index format 2 rebuilds the DN, child and
   equality indexes atomically on first open after upgrading. Downgrading a store with
   escaped DNs needs a pre-upgrade backup.
7. **Generated TLS certificates** ([#17](https://github.com/hilather/go-lab-ldap-mcp/pull/17)). Leaves minted by earlier `setuptls`
   lack Authority Key Identifier and are rejected by strict clients (for example
   Python 3.14 with OpenSSL). Re-mint with `--force`; this rotates the lab CA, so
   clients must update trust.
8. **Cached revision tokens rotate** ([#18](https://github.com/hilather/go-lab-ldap-mcp/pull/18)). User and account endpoints share one
   opaque revision that now includes the public lock and must-change state, so
   existing cached tokens rotate after upgrading; clients must refresh before their
   next mutation. The design is in ADR-0012, which is still proposed for owner
   review.

**Still open, not decided here:** whether the stricter user attribute names ([#27](https://github.com/hilather/go-lab-ldap-mcp/pull/27),
[#18](https://github.com/hilather/go-lab-ldap-mcp/pull/18)) need an `apiVersion` bump. This tag keeps `apiVersion: labldap.dev/v1alpha1`
and leaves that owner decision open.

## Highlights since v0.5.0

Security and correctness

- Directory policy and reset isolation: protected attribute aliases and secret-bearing
  filters are rejected before LDAP; reset drains admitted operations and restores the
  full baseline across all managed suffixes; export and rate-limit resources are
  bounded; bootstrap keeps the configured LDAP dial timeout ([#18](https://github.com/hilather/go-lab-ldap-mcp/pull/18)).
- Native LDAP authorization and rename safety: per-assertion search checks in filters
  and RFC 4528 assertions, self/descendant ModifyDN rejected, RDN attribute write
  checks, structural DN identity with an atomic index migration, bounded search size
  and time, indexed equality search, and the operation subject captured before a later
  Bind ([#19](https://github.com/hilather/go-lab-ldap-mcp/pull/19)).
- Directory mutations are serialized across the user and structured-entry APIs, so
  two DN spellings or two APIs can no longer both pass a stale revision ([#22](https://github.com/hilather/go-lab-ldap-mcp/pull/22)).
- Native hashes `userPassword` written under an option spelling over direct LDAP;
  389 stores it as written (accepted delta D31) ([#25](https://github.com/hilather/go-lab-ldap-mcp/pull/25)).

Native parity with the pinned 389 image

- `rfc822Mailbox`/`gn` aliases and stricter user attribute names ([#27](https://github.com/hilather/go-lab-ldap-mcp/pull/27)).
- Filter attribute descriptions, search-result visibility and `||` targetattr lists
  ([#28](https://github.com/hilather/go-lab-ldap-mcp/pull/28); CAND-31 and CAND-32 resolved).
- `targetattr` schema check, options and omitted `targetattr` ([#29](https://github.com/hilather/go-lab-ldap-mcp/pull/29); CAND-33,
  CAND-34 and CAND-35 resolved; delta D36).

Console

- Account inspect/lock/unlock, require/clear password expiry, set password with
  `mustChange`, and structured entry attribute add/replace/delete; edit, move and
  delete keep the revision from the start of the draft and ask to refresh on conflict
  ([#20](https://github.com/hilather/go-lab-ldap-mcp/pull/20)).

TLS, release and build

- `setuptls` signs leaves with the issued CA, so they carry Authority Key Identifier
  ([#17](https://github.com/hilather/go-lab-ldap-mcp/pull/17)).
- Release gates fail on parity or 389 integration failures; CI adds browser, oracle
  and native fuzz/soak jobs; `image-pair-check`; opt-in `make test-e2e-live`
  ([#21](https://github.com/hilather/go-lab-ldap-mcp/pull/21)).
- Test-harness flake fixes: wait for the Directory Manager password before binding,
  and parse only the bootstrap summary object ([#26](https://github.com/hilather/go-lab-ldap-mcp/pull/26); test code only).
- Go toolchain `go1.26.8`; the five expired standard-library exceptions are retired
  because the toolchain fixes them ([#16](https://github.com/hilather/go-lab-ldap-mcp/pull/16)).
- MIT `LICENSE` (OD-003 resolved) ([#14](https://github.com/hilather/go-lab-ldap-mcp/pull/14)); `MANIFEST.md` ADR rows point at the
  stubs and list accepted ADRs 0008–0011 ([#15](https://github.com/hilather/go-lab-ldap-mcp/pull/15)).
- Proposed, not accepted: ADR-0013 native security floors ([#23](https://github.com/hilather/go-lab-ldap-mcp/pull/23)) and ADR-0014 Bind
  with outstanding operations ([#24](https://github.com/hilather/go-lab-ldap-mcp/pull/24)).

## Details: user attribute names and aliases ([#27](https://github.com/hilather/go-lab-ldap-mcp/pull/27))

The open `apiVersion` question is under Upgrade risks above. User attribute writes from REST, MCP, the console and scenario YAML
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

`rfc822Mailbox` and `gn` are now resolved as `mail` and `givenName`
(#18 follow-up):

- Users (REST, MCP, console, YAML) with both spellings of one attribute
  (`mail` + `rfc822Mailbox`, `givenName` + `gn`) get `duplicate_attribute`.
  Duplicate detection now walks names in case-insensitive order, so the
  error lands on the later name in that order; for existing pairs the
  field changes, e.g. `OU` + `organizationalUnitName` now flags `OU`.
  Forbidden-name checks share that walk, so when a request or scenario
  has several forbidden names, the first one reported can change too.
- User writes, YAML seeding, entry create and entry-update replace/add send
  every resolved second descriptor (also `organizationalUnitName`,
  `domainComponent`, `organizationName`) under its primary name. A
  scenario that uses such keys gets a new directory revision, so a
  persistent deployment in `startupMode: validate` needs one merge apply
  after upgrading.
- Entry create keeps the first of `mail` + `rfc822Mailbox` (`mail`) and of
  `givenName` + `gn` (`givenName`).
- `PATCH {"gn": ""}` now deletes `givenName` (it was silently skipped), and
  the empty-value delete finds attributes stored under another case (a
  YAML-seeded `givenname` on native).
- Native persistent stores that already hold an unknown `rfc822Mailbox` or
  `gn` attribute keep it. Those values are visible and removable only
  through the entry API (delete of the alias spelling, which on native
  leaves `mail`/`givenName` untouched; parity delta D35) or a reset, never
  through the user view. On a native store seeded on an older release with
  YAML `gn: X`, the first merge apply after upgrading adds `givenName: X`
  and reports the user as Updated once.
- The console tree editor refuses replace and add for every alias name
  (not only `rfc822Mailbox`/`gn`): a replace of `commonName` would change
  `cn`. It allows delete only for a row stored under the alias spelling.
- An entry-update delete of an optioned alias (`rfc822Mailbox;lang-en`)
  with no row stored under that spelling now removes the `mail;lang-en`
  value its add wrote, on both engines (it answered 404 on native).
- An LDAP `noSuchAttribute` result (a delete of an attribute or value the
  entry does not hold) now answers HTTP 409 with field `attribute` /
  `conflict` instead of 404 "directory entry not found".
- Native search filters resolve second descriptors (see the filter
  section below): `(rfc822Mailbox=x)` matches `mail`. Compare and search
  attribute lists still match names literally and do not resolve aliases.

## Details: filter attribute descriptions and ACI visibility ([#28](https://github.com/hilather/go-lab-ldap-mcp/pull/28))

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

Native ACI evaluation now follows 389 in two more places. Search results
leave out an entry unless the subject can read at least one
non-operational attribute it holds; before, native returned such entries
with only their DN. `targetattr` lists are separated by `||`, numeric OIDs
are accepted, and every name is compared literally, so a numeric OID does
not cover the attribute's name (a deny on `2.5.4.35` does not deny
`userPassword`). Native logs a warning at startup for each numeric-OID
`targetattr` name; use attribute names instead. A raw ACI that used a
single `|` as a separator (`"cn|sn"`) is now rejected at startup, as 389
already rejected it: the server exits with a configuration error on
`aciTexts` ("ACI text failed to parse: ... invalid attribute name
\"cn|sn\" in targetattr"). Rewrite it as `"cn || sn"`.

## Details: ACI targetattr schema, options and entry-level checks ([#29](https://github.com/hilather/go-lab-ldap-mcp/pull/29))

Native ACI evaluation now matches the pinned 389 image in four more places
(contract C8; oracle probes 16-20; CAND-33, CAND-34 and CAND-35 resolved):

- **Unknown `targetattr` names are rejected.** A name must be an attribute
  type, alias, numeric OID or `-oid` placeholder in the pinned 389 schema
  (options are not checked). A raw ACI naming anything else (a typo, an
  object class such as `person`, the native-only `pwdChangedTime`) now
  stops labldapd at startup with `aciTexts` / `invalid_aci` ("targetattr
  ... does not exist in the 389 schema"), as 389 refuses the ACI add with
  invalidSyntax(21). A DSL ACL naming one in `attributes.allow` or
  `attributes.deny` fails `labldap` config validation with
  `unknown_attribute` on `spec.acls.<id>.attributes.allow|deny`.
- **Options in `targetattr` narrow the rule.** `targetattr="uid;x-test"`
  now covers only `uid;x-test` (and descriptions with more options), not
  all of `uid`; `targetattr!="uid;x-test"` excludes only those. An empty
  option (`"uid;"`) covers nothing. This is 389's answer on a fresh
  connection; 389 can reuse an earlier decision for the plain type on the
  same connection, native never does (delta D36).
- **An omitted `targetattr` targets no attribute.** Such an ACI now
  applies only to add, delete and the modrdn entry gates; before, native
  treated it as `targetattr="*"`. Add `(targetattr="*")` to keep the old
  meaning.
- **No entry-level search or Modify check.** `deny (search)
  targetattr="userPassword"` now hides only `userPassword` filter leaves
  instead of every entry. Modify checks write on each changed attribute,
  so an attribute-scoped deny-write blocks only changes to that
  attribute; all changes are checked before the entry lookup and the
  assertion control, so a subject without write gets 50, never 32.

ACI checks also resolve second descriptors, so a value written as `userid`
is covered by `targetattr="uid"` (389 stores it as `uid`), and a filter
leaf with an empty option (`(cn;=x)`) matches nothing, as on 389.

Upgrade risk: these changes can **widen** access for existing raw ACIs.
A deny ACI without `targetattr` no longer denies attribute reads or writes;
a `deny (search)` or `deny (write)` scoped to some attributes no longer
hides or locks whole entries. They can also **narrow** access: an allow
ACI without `targetattr`, or with an option-bearing name, stops granting
reads, searches and writes on the plain attribute. Review raw ACIs before
upgrading (DSL ACLs always emit an explicit `targetattr`). ModRDN keeps
the stricter native entry gates (CAND-36), and absolute filters such as
`(&)` keep the entry-level search check (CAND-38). Separately, a DSL ACL
with more than one name in `attributes.allow` or `attributes.deny` still
compiles to `targetattr="*"`; this pre-existing over-grant is tracked as a
follow-up and not changed here.

## Versions

| Component | Pin |
| --- | --- |
| LabLDAP source | `v0.6.0` (`git describe`; see `dist/release/provenance.json`) |
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
  389 is still the oracle. Open candidates: CAND-36 (modrdn entry gates with an
  attribute-scoped deny-write), CAND-37 (`targetattr!="*"`), CAND-38 (absolute
  filters keep the entry-level search check).
- A DSL ACL with more than one name in `attributes.allow` or `attributes.deny` still
  compiles to `targetattr="*"`; this pre-existing over-grant is a tracked follow-up.
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

v0.5.0 → v0.6.0 keeps `apiVersion: labldap.dev/v1alpha1`; REST, MCP and
config shapes are unchanged. Read "Upgrade risks" first.
Exceptions for native-engine raw ACIs: a `targetattr` list separated by
a single `|` must be rewritten with `||`, every `targetattr` name must
exist in the 389 schema, and ACIs without `targetattr` or with
option-bearing names change meaning (see "ACI targetattr schema, options
and entry-level checks" above); review them before upgrading. `labldap` config
validation does not parse raw ACI text, so the failure appears only when
labldapd starts.

1. Default `make compose-up` with the shipped scenario needs no config change.
2. Raw ACIs (`allowRawACI: true`): check every `targetattr` name against the 389
   schema, rewrite single-`|` lists as `||`, add `(targetattr="*")` where an ACI
   without `targetattr` was meant to cover attributes, and review option-bearing names
   and attribute-scoped search/write denies.
3. DSL ACLs: every name in `attributes.allow` / `attributes.deny` must exist in the
   389 schema.
4. Scenario YAML: remove forbidden or duplicate user attribute spellings; a scenario
   that uses second descriptors (`rfc822Mailbox`, `gn`, `organizationalUnitName`, …)
   gets a new directory revision, so a persistent deployment in
   `startupMode: validate` needs one merge apply after upgrading.
5. Persistent native volume: the first start rebuilds indexes (formats 2 and 3). Take a
   backup before upgrading if you may downgrade; roll back image tags/digests
   together.
6. Re-mint generated TLS with `setuptls generate --force` (rotates the lab CA) if
   strict clients reject the old leaves.
7. Clients holding user/account revision tokens must re-read before mutating.
8. Tokens, TLS file layout, ports, MCP flags and password-policy YAML are unchanged.

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
- Dual-engine parity for the attribute, filter and ACI changes ([#27](https://github.com/hilather/go-lab-ldap-mcp/pull/27)–[#29](https://github.com/hilather/go-lab-ldap-mcp/pull/29)).

Security: the toolchain is `go1.26.8`, which fixes the five standard-library
advisories that v0.4.1 and v0.5.0 carried as dated exceptions; there are no approved
exceptions. See
[dependency-policy.md](https://github.com/hilather/go-lab-ldap-mcp/blob/main/docs/security/dependency-policy.md).

## Earlier releases

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
