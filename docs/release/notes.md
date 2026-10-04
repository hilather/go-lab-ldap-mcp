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

## Unreleased: ACI targetattr schema, options and entry-level checks (native engine)

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

## Unreleased: modrdn gates, star lists, absolute filters and DSL attribute lists

For the release after the CAND-33/34/35 changes above. Native now matches
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
  `targetattr="*"` (the over-grant noted above is fixed), `attributes.deny`
  with no allow list emits `targetattr!="a || b"`, and both lists emit
  the allow names that no deny name covers. New validation errors on
  `spec.acls.<id>.attributes.deny`: `invalid_attribute_filter` for a deny
  name with options narrower than a same-attribute allow name, for a
  combination that leaves no attribute, and for `deny: ["*"]` (it used to
  compile; remove the ACL or narrow it). More than 64 names in one list
  fail schema validation (`too_many_attributes` in the compiler).

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

## Migration guidance

v0.4.0 → v0.4.1 is **additive**. `apiVersion` stays `labldap.dev/v1alpha1`.
Exceptions for native-engine raw ACIs: a `targetattr` list separated by
a single `|` must be rewritten with `||`, every `targetattr` name must
exist in the 389 schema, and ACIs without `targetattr` or with
option-bearing names change meaning (see "ACI targetattr schema, options
and entry-level checks" above); review them before upgrading. `labldap` config
validation does not parse raw ACI text, so the failure appears only when
labldapd starts.

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
