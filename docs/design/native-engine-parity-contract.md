# Native engine parity contract

**Status:** accepted with [ADR-0008](../adr/0008-dual-directory-engines.md) and [ADR-0009](../adr/0009-native-engine-topology-and-storage.md)

**Version:** `labldap.parity.v1`

**Date:** 2026-08-15

**Oracle:** pinned 389 Directory Server 2.4.6 (digest in `deploy/docker/dirsrv.digest`)

**Subject:** Go-native engine (`cmd/labldapd`, `internal/ldapserver`)

This file is the Contract / Delta / Excluded ledger for dual-engine work. Expanding the Contract tier, shrinking Excluded, or promoting a Delta to Contract requires a dated amendment here and, if it changes a public engine guarantee, an ADR.

Agents implementing M9 tasks must read this document and the two ADRs before writing code.

## 1. How to use this contract

| Tier | Meaning | Test obligation |
| --- | --- | --- |
| **Contract** | Both engines must produce the same *directory-visible* result for LabLDAP clients and the control plane. | Dual-engine case in `test/parity` (T-147+) or a parametrized integration test. 389 is oracle. |
| **Delta** | Intentional, documented difference. Native must not fake 389 identity. | Assert the *difference* (or skip with a named delta ID). |
| **Excluded** | 389 behavior LabLDAP does not expose. Native must not implement it in M9. | No parity case. Implementing it is scope creep; stop and amend this file. |

**Compare normalized results, not raw bytes.** DN comparison uses `internal/config` canonical DN rules. Search result order is not Contract unless a test sorts. Password hashes are never compared; bind success/failure and policy *effects* are.

When a test fails: (1) confirm 389 still matches the contract; (2) fix native; (3) only if 389 is uniquely quirky and LabLDAP does not depend on the quirk, add a Delta with evidence (389 result, native result, why LabLDAP does not care).

## 2. Contract features

### C1. Wire protocol

LDAPv3 (RFC 4511) operations:

| Operation | Notes |
| --- | --- |
| Bind (simple) | Anonymous bind follows `spec.transport.allowAnonymousBind` (default false). |
| Unbind | Closes the connection; no response PDU required (RFC 4511). |
| Search | base / one / sub; `children` if advertised. Size and time limits always applied. |
| Add / Modify / Delete / Compare / ModifyDN | ModifyDN required for completeness; LabLDAP runtime may not call it. |
| Abandon | Cancels an outstanding op on that connection. |
| Extended | StartTLS; WhoAmI (`1.3.6.1.4.1.4203.1.11.3`, RFC 4532). **Not** RFC 3062 Password Modify (see C11). |

Message ID correlation, protocolOp tagging, and LDAPResult codes used by the control plane (`success`, `operationsError`, `protocolError`, `authMethodNotSupported`, `strongAuthRequired`, `noSuchObject`, `aliasProblem` unused, `invalidDNSyntax`, `insufficientAccessRights`, `busy`, `unavailable`, `unwillingToPerform`, `constraintViolation`, `entryAlreadyExists`, `invalidCredentials`, `inappropriateAuthentication`, `objectClassViolation`, `namingViolation`, `notAllowedOnNonLeaf`, `affectsMultipleDSAs` (moves between managed suffixes, CAND-39), `sizeLimitExceeded`, `timeLimitExceeded`, `adminLimitExceeded`, `unavailableCriticalExtension`, `confidentialityRequired`) are Contract where the product maps them (`internal/directory/ldapclient/errors.go`).

### C2. Transports

| Transport | Port (compose default) | Contract |
| --- | --- | --- |
| LDAP | 3389 | Accepts StartTLS when enabled; rejects cleartext simple bind when `allowCleartextBind` is false. |
| LDAPS | 3636 | TLS required before any bind. |
| StartTLS | 3389 then extended op | Same trust rules as 389 mode (CA + name). |

Wrong CA and wrong server name fail closed. Independent clients in `test/compatibility` must pass against native once T-148 lands.

### C3. Authentication and bind policy

- Simple bind against `userPassword`.
- Directory Manager (`cn=Directory Manager`) bypasses ACI; password from file, never argv.
- Anonymous bind default off.
- Cleartext simple bind default off.
- SASL: none required (no YAML `RequiredSASL` today). Native advertises none. See E2.
- Disabled account: `nsAccountLock: true` → bind fails with LDAP 53 (`unwillingToPerform` / unwilling) matching 389 observed behavior in `test/integration/dirsrv/plugins_test.go`.
- Lockout: after configured failures, bind fails and `pwdAccountLockedTime` is present on the entry (bind-test reads this attribute).

Unknown user vs wrong password remain indistinguishable on the **management** bind-test API. Direct LDAP result codes may follow 389 (typically `invalidCredentials` for both).

### C4. Password policy (bind-time effects)

Public policy fields in `spec.passwordPolicy` that 389 applies via `dsconf pwpolicy` must have the same *bind and modify* effects:

| Field | Contract effect |
| --- | --- |
| Minimum length | Add/modify `userPassword` rejected when too short. |
| History | Reuse of a recent password rejected. |
| Maximum age | Expired password cannot bind (or must change — match 389 observed). |
| Warning | Operational; if 389 exposes it, native may expose the same operational attr; not required on management APIs. |
| Lockout max failures + duration | Bind lockout + `pwdAccountLockedTime`. |
| Storage scheme | `PBKDF2-SHA256` (default) and `SSHA512` hashes **verify**. Hash *encoding* is Delta D3. |

Passwords are never returned, logged, or placed on argv.

### C5. Tree shape, object classes, attributes

| Object | Object classes | Notes |
| --- | --- | --- |
| Suffix root | `top`, `domain` | |
| `ou=people`, `ou=groups` | `top`, `organizationalUnit` | RDN configurable. |
| Users + runtime account | `top`, `person`, `organizationalPerson`, `inetOrgPerson` | `config.RequiredUserObjectClasses()`. |
| Groups | `top`, `groupOfNames` | Empty groups forbidden (OD-018). |
| Baseline marker | `top`, `device` | `cn=labldap-baseline,<suffix>`; namespaced JSON in `description` (OD-012). |
| MemberOf overlay | auto-add `nsmemberof` | When memberOf plugin enabled. |

Attributes the product reads or writes: `uid`, `cn`, `sn`, `givenName`, `mail`, `displayName`, `description`, `userPassword`, `member`, `memberOf`, `nsAccountLock`, `pwdAccountLockedTime`, `aci`, plus operational `createTimestamp`, `modifyTimestamp`, `modifiersName`, `entryUUID` (entryUUID format may be Delta if 389’s namespace differs; *presence* after add is Contract).

`userPassword`, `memberOf`, and operational attributes remain forbidden in scenario YAML user `attributes`.

### C6. Search and filters

- RFC 4515 filter parse; malformed filters fail safely (no injection into evaluation).
- Scopes: base, one, subtree.
- Search cannot escape the requested base; control plane additionally refuses bases outside the managed suffix — that check stays in the control plane.
- Simple Paged Results control `1.2.840.113556.1.4.319`.
- Server size and time limits always applied.
- Equality matching: `caseIgnoreMatch` for name-like attrs, `caseIgnoreIA5Match` where 389 uses it for `uid`/`mail` if observed; DN equality is structural via canonical DN, not string suffix.
- Substring filters used by the UI/search console must work.
- Attribute descriptions in filter leaves follow 389 (oracle probes 1-7 against the pinned image; transcripts in `test/parity/testdata/filter-attr-oracle-probes.txt`): RFC 4512 §2.5 subtype semantics. A description without options matches the type and all its subtypes (`(description=hello)` matches a value stored as `description;lang-en`); a description with options matches only values whose stored option set contains them (case-insensitive, any order; no language ranges, so `description;lang-` matches nothing). A numeric OID or second descriptor (`userid`, `commonName`, `2.5.4.0`) resolves to the type only when it carries no options; with options (`userid;x-test`, `2.5.4.3;lang-en`) the leaf is False, so its NOT is True. Search permission for a leaf is checked against the resolved type, or for an unresolved spelling against its literal base name; ACI `targetattr` lists are compared literally (no alias or OID resolution). Assertion-control filters (native only, D7/D28) and rootDSE/subschema filters share these semantics; write, read and compare ACI checks resolve the requested or stored attribute (OID or second descriptor to the type name, so a value written as `userid` is checked as `uid`, as 389 stores it; probe 20) and match its options against `targetattr` options (C8), but `targetattr` names are never resolved, so an OID-named `targetattr` does not cover that attribute. An empty option in a filter leaf (`cn;`, `cn;lang-en;`) matches nothing, even for Directory Manager (probe 20b). Compare does not take these semantics (D34). `;binary` is untested and out of scope. `TestFilterAttributeDescriptions`, `TestFilterLeafSearchIdentityMatchesOracle` (`internal/ldapserver`), `TestDualEngineFilterAttributeDescriptionParity` (`test/parity`), `TestFilterAttributeDescriptionsAreEngineNeutral` (`test/integration/dirsrv`).

### C7. Groups, memberOf, referential integrity

- Forward membership is `groupOfNames` `member` (full DN).
- `memberOf` is derived. Membership add/remove/replace updates `memberOf` before the LDAP result returns (389 MemberOf plugin with fixup). Native: same-commit write-path plugin plus a fixup equivalent for bootstrap/reset.
- Nested groups follow `spec.directory.nestedGroups`.
- User (or group) delete repairs `member` references (referential integrity, update-delay 0, suffix-scoped). 389 observed: `test/integration/dirsrv/plugins_test.go`.

### C8. Access control

Native must evaluate the ACI **text the LabLDAP compiler already emits**, including golden fixtures under `internal/config` and `internal/config/testdata/runtime-acis.txt`.

Supported grammar (compiler subset, plus `||` lists and numeric-OID `targetattr` names accepted from raw ACIs):

```text
(target="ldap:///<dn>")
(targetattr="<attr>[ || <attr>...]" | "*" | targetattr!="<attr>[ || <attr>...]")   # "*" may appear in a list and after !=
(version 3.0; acl "<name>"; allow (<perm>,...) <who>;)
```

| Clause | Contract |
| --- | --- |
| `target` | Entry is that DN or a descendant. |
| `targetattr` / `targetattr!` | Attribute allow or deny. Lists are separated by `\|\|` with any surrounding spaces; a single `\|` is rejected. Names may be descriptors or numeric OIDs, with options. Every name is compared literally: case-insensitive, with no alias or OID resolution. So `"2.5.4.4"` does not cover `sn`, and a deny on `"2.5.4.35"` does not deny `userPassword` on either engine. Native logs a warning at startup for each numeric-OID name (oracle probes 8, 10, 11, 14; resolved CAND-32). Every name must exist in the pinned 389 schema (an attribute type's name, alias, numeric OID or `-oid` placeholder; options are not checked): 389 rejects the ACI add with invalidSyntax(21), native fails startup (`invalid_aci`) and the compiler rejects a DSL ACL (`unknown_attribute`). The list is embedded from the pinned image (`internal/schema389`, probes 16, 17, 19; resolved CAND-33). A name with options covers only attribute descriptions that carry all of them (case-insensitive, any order): `targetattr="uid;x-test"` covers `uid;x-test` and `uid;x-test;x-two` but not `uid`, and `targetattr!="uid;x-test"` excludes only those; an empty option (`uid;`) covers nothing (probes 12, 16, 18; resolved CAND-34). This is 389's answer on a fresh connection; on a reused connection 389 can apply an earlier decision for the plain type instead (D36). An omitted `targetattr` targets no attribute, so the ACI applies only to entry-level checks: add, delete and the modrdn entry gates (probes 16, 18, 19; resolved CAND-35). `"*"` may appear inside a list and after `!=`, as on 389: a positive list holding `"*"` (`"* || sn"`) covers every attribute, and a negated list holding it (`targetattr!="*"`, `!="* || sn"`) covers no attribute, so such an ACI applies only to add, delete and the cross-parent move gate (CAND-39); it does not block a same-parent rename, whose entry gate counts only ACIs without `targetattr` (probes 25, 26; resolved CAND-37). DSL `attributes.allow`/`attributes.deny` compile to one such list: allow alone to `targetattr="a || b"` (`"*"` or no list: `"*"`), deny with an empty or `"*"` allow list to `targetattr!="a || b"`, both to the allow names no deny name covers (same base after resolving 389 aliases from the pinned schema, deny options a subset of the allow name's); every emitted name is the 389 NAME with its options (`userid` becomes `uid`, `pwdHistory` becomes `passwordHistory`), since `targetattr` names are compared literally; a deny with options narrower than a same-base allow name, a combination leaving no name, `deny: ["*"]` and more than 64 names are rejected (`invalid_attribute_filter`, `too_many_attributes`), and numeric OIDs and names with an empty option are `invalid_attribute` (resolved DSL follow-up). `TestTargetAttrStarListsMatchOracle`, `TestACLAttributeListsAre389Lists`, `TestTargetAttrSchemaCheckMatchesOracle`, `TestTargetAttrOptionsAndEntryLevelSearchMatchOracle`, `TestTargetAttrOptionsMatchProbe12`, `TestACLAttributesMustExistIn389Schema`, `TestACITargetAttrOptionsAndEntryLevel` and `TestTargetAttrUnknownNameRejected` (`test/integration/dirsrv`), `TestDualEngineFilterAttributeDescriptionParity` `fattr35` rows (`test/parity`). |
| Search result visibility | There is no entry-level search check, as on 389: each evaluated filter leaf needs search on its own attribute (C6), so `deny (search) targetattr="userPassword"` denies only `userPassword` leaves (probes 14, 16; resolved CAND-35). A filter holding an absolute true/false set (`(&)`, `(\|)`, RFC 4526) anywhere, including under NOT, is rejected with protocolError(2) "Bad search filter" for every subject and base (Root DSE, `cn=schema`, an invalid or missing base), before any control is processed; the connection stays open (probes 19, 25, 26, 28, 29; resolved CAND-38; `TestAbsoluteFilterRejectedMatchesOracle`). The assertion control keeps its own handling: 389 refuses the control itself with unavailableCriticalExtension(12) (CAND-19). An entry is returned only if the subject may read at least one non-operational attribute it holds, in every scope (native checks this after the filter). objectClass and memberOf count; operational attributes do not: entryUUID, nsUniqueId (389 only), the timestamps, creatorsName/modifiersName, nsAccountLock, aci, passwordHistory and the native-only pwdChangedTime. "Operational" is the native schema registry flag, overridden where 389's `cn=schema` usage differs (memberOf counts; nsAccountLock and aci do not; probe 15 compared every registry attribute). Stored OID or alias spellings are resolved first; attributes unknown to the registry count. Filter leaves still need search on their own identity (C6). Probes 8, 10, 12 (base scope), 13 and 15; resolved CAND-31. memberOf and nsAccountLock rows run on both engines; passwordHistory and pwdChangedTime are unit-tested only, because the engines write them differently. `TestSearchEntryVisibilityMatchesOracle`, `TestSearchVisibilityOperationalOverridesMatchOracle`, `TestDualEngineFilterAttributeDescriptionParity`, `TestACIEntryVisibilityAndTargetAttrLists` (`test/integration/dirsrv`). |
| Modify | No entry-level write check, as on 389: each change needs write on its own attribute, so an attribute-scoped deny blocks only changes to that attribute. All changes are checked in request order (ACI, then the operational-attribute rule) before the entry is read and before the assertion control, so a subject without write gets insufficientAccessRights(50) for a missing entry, not noSuchObject(32) (probes 16, 18; resolved CAND-35). |
| ModRDN | Same-parent rename (newSuperior absent or equal to the current parent), as on 389 with `nsslapd-moddn-aci` on: the subject needs write on the new RDN attribute on the old DN, even when the value is unchanged, and with deleteoldrdn write on the old RDN attribute too; at entry level only a deny-write ACI without `targetattr` covering the old DN blocks (attribute-scoped denies, including `!=` and negated star lists, do not); no add right is needed and ACIs covering only the new DN do not count (probes 25-27; resolved CAND-36). Renaming an entry to its own stored DN (compared with the stored spelling) is success and updates `modifyTimestamp`/`modifiersName` without touching the RDN values (probe 28). Result-code order for subjects without Directory Manager: a missing source is insufficientAccessRights(50) unless the subject holds `moddn` on it (see the move rule below; Directory Manager gets noSuchObject(32)); a rename onto an existing DN is entryAlreadyExists(68) and a move beneath itself unwillingToPerform(53), both before any access check, so these two codes disclose existence to subjects without rights, as on 389 (probe 27). A new RDN of an undefined type is 50 without write on it; with write 389 answers 65 while native does not check undefined types on writes (CAND-8). A move to a different parent (resolved CAND-39, probes 26, 30-34) needs `moddn` on the new superior, checked at entry level (`targetattr` is ignored; an ACI targeting only the new DN does not count), plus the same gates on the old DN as a rename; no add, delete or source-side `moddn` is checked. A missing source or new superior is noSuchObject(32) for Directory Manager and for a subject holding `moddn` on that DN through an ACI whose `targetattr` covers an arbitrary attribute (none, `"*"`, a list holding `"*"`, or a negated list without `"*"`, allows and denies alike), else insufficientAccessRights(50); a missing superior is reported before the write checks. Subtrees move with their children; referint rewrites member values naming the moved entry or a descendant, and memberOf follows. A move between managed suffixes is affectsMultipleDSAs(71) for every subject before any existence or access check (renaming a suffix root stays 53 first; a missing superior beneath the source answers 53, unprobed) (389 backends; REST/MCP refuse it up front with a `newDN` forbidden field error); moves outside the managed suffixes stay 53 (D11). A case-only rename (resolved CAND-30) succeeds with the rename gates and respells the DN (children follow); member values and memberOf are left as written. The new DN takes the request's own parent spelling for a rename (an explicit equal newSuperior is ignored) and the stored superior's spelling for a move; a rename that changes only the parent spelling respells it, and only a request whose resulting DN equals the stored spelling is a no-op. Attribute types are lowercased on native (D37). `target_from`/`target_to` are not supported (D38). Native evaluates ACIs as 389 with `nsslapd-moddn-aci` on (the pinned image's default). `TestModifyDNRenameMatchesOracle`, `TestModifyDNOrderingMatchesOracle`, `TestModifyDNNoOpRename`, `TestACIModRDNStarListsAbsoluteFilters`, `TestModDNMatchesOracle`, `TestRESTMovesWithRuntimeGrant` (`test/integration/dirsrv`), `TestModDNMovesMatchOracle`, `TestModDNExistenceMatchesOracle`, `TestModDNCaseOnlyMatchesOracle`, `TestModDNSpellingMatchesOracle`, `TestModDNPluginsMatchOracle` (`internal/ldapserver`), `TestDualEngineCand3638Parity` (`test/parity`). |
| Permissions | `read`, `search`, `compare`, `add`, `delete`, `write` as emitted, and `moddn` (runtime ACIs and raw ACIs; resolved CAND-39). The DSL `permissions` list has no `moddn`. |
| `userdn="ldap:///<dn>"` | Bound user. |
| `groupdn="ldap:///<dn>"` | Bound user is a `member` of that group. |
| `userdn="ldap:///anyone"` | Authenticated or not — match 389 observed for compiler output. |
| `userdn="ldap:///all"` | Used if a builder emits it. |

Evaluation order: **deny-wins** among applicable ACIs if 389 does; otherwise match 389 observed on the T-036 matrix. Do not invent extra 389 ACI features (`targattrfilters`, `ssf`, `ip`, `dns`, `dayofweek`, `authmethod` SASL, `deny` ACI statements) unless the compiler starts emitting them — that would amend this section.

Runtime ACI set is always present:

1. `labldap:runtime-suffix-read` — read/search/compare on suffix, `targetattr!="userPassword"`
2. `labldap:runtime-people-write` — CRUD on people, `targetattr!="aci"`
3. `labldap:runtime-groups-write` — CRUD on groups, `targetattr!="aci"`
4. `labldap:runtime-password` — write `userPassword` on people

Plus operator ACLs from YAML. Raw ACI (`allowRawACI`) is Contract: native must parse and enforce any raw text that is still inside this grammar; raw text outside the grammar is a documented rejection or a new Delta, never silent ignore.

T-036 probes (runtime allow/deny, including `cn=config` denial) are Contract. Native may have no `cn=config` DIT (Delta D2) but the runtime identity must still be denied any engine-admin tree.

### C9. Controls and atomic updates

| Control | OID | Contract |
| --- | --- | --- |
| Simple Paged Results | `1.2.840.113556.1.4.319` | List/search/inventory/export paging. |
| Assertion (RFC 4528) | `1.3.6.1.1.12` | Advertised on Root DSE. Used by If-Match updates. Must be transactional (ADR-0009). If native advertises it, it must honor it; do not advertise and no-op. |

Critical unsupported controls → `unavailableCriticalExtension`.

### C10. Schema and Root DSE publication

- Root DSE search (empty DN, base) returns `namingContexts`, `supportedControl`, `supportedExtension`, `vendorName`/`vendorVersion` (values are Delta D1), `supportedLDAPVersion`.
- Subschema subentry is searchable; object classes and attributes used in C5 are present.
- Capability inspector (`T-044` shape) is measured, not name-assumed. `requiredOK` fails bootstrap when a Contract capability is missing.

### C11. Password modify path

LabLDAP and the T-115 matrix use **attribute replace on `userPassword`**, not RFC 3062. Native must accept that modify. RFC 3062 is Excluded (E3) unless later added.

### C12. Soft reset, export, marker

- Inventory, dependency-safe delete, baseline reapply, marker last — control-plane behavior, engine-agnostic if C5–C8 hold.
- Marker written last; partial apply does not commit a new marker.
- LDIF export encoding is control-plane (`internal/directory/ldif.go`); engine must support the searches export uses.
- Seed users bind with seed passwords after reset.

### C13. Direct LDAP visibility

A user created through REST or MCP is visible to `ldapsearch` against the directory listener, and a user added with `ldapmodify` as DM is visible through REST. This is the original product guarantee and is Contract for both engines.

## 3. Deltas (intentional)

| ID | Topic | 389 | Native | Test |
| --- | --- | --- | --- | --- |
| D1 | Vendor identity | `389-Directory/2.4.6 …`, `engineVendor` 389 | Distinct `vendorName` / `engineVendor` (e.g. `LabLDAP`) and `engineVersion` = labldap version | Assert inequality; do not require 389 strings. |
| D2 | Admin plane | `cn=config`, `dsconf`, plugin CNs, `nsslapd-*` | No `dsconf`. Engine plan applied at `labldapd` start. `cn=config` may be absent or a stub that denies the runtime account. | Bootstrap native reconcilers read back via LDAP/Root DSE, not CLI. |
| D3 | Password hash encoding | 389 `PBKDF2-SHA256` / `SSHA512` wire form | Same schemes, possibly different encoded blobs | Bind with the plaintext; never compare hashes across engines. |
| D4 | On-disk format | 389 `/data` (nsslapd db) | bbolt `/data/labldapd.bolt` | Lifecycle tests (ephemeral/persistent) only. |
| D5 | Backend name | `userroot` via `dsconf backend` | Suffix exists; backend name need not be `userroot` | Do not assert backend CN on native. |
| D6 | Root DSE extra attrs | 389-specific operational attrs | Honest advertisement; omit unknown 389 extras | Capabilities test uses allowlisted fields. |
| D7 | Assertion absence path | If 389 ever omits RFC 4528, control uses TOCTOU+lock | Native **must** advertise and honor RFC 4528 | Native-only assertion atomicity test. |
| D8 | Bind with malformed DN | `invalidDNSyntax(34)` | `invalidCredentials(49)` | `TestDifferential389Oracle/bind-malformed-dn`; see parity-delta-log.md. |
| D9 | Anonymous bind while disabled | `inappropriateAuthentication(48)` | `unwillingToPerform(53)` | `TestDifferential389Oracle/anon-bind-disabled`; CAND-1 adjudicated 2026-08-15. |
| D10 | LDAPv2 bind attempt | `invalidCredentials(49)` | `protocolError(2)` | `TestDifferential389Oracle/bind-version-2`. |
| D11 | ModifyDN with a `newSuperior` outside every managed suffix (moves between managed suffixes are 71 on both, CAND-39) | `affectsMultipleDSAs(71)` | `unwillingToPerform(53)` | `TestDifferential389Oracle/modifydn-cross-suffix`; CAND-4 adjudicated 2026-08-15. |
| D12 | Paged-results cookie tamper | Accepts tampered cookie (`success`); no integrity protection | HMAC-signed cookie fails closed, `unwillingToPerform(53)` | `TestDifferential389Oracle/paged-tampered-cookie`; CAND-5/CAND-18 adjudicated 2026-08-15. |
| D13 | WhoAmI bound authzId rendering | `dn: <case-folded dn>` | `dn:<as-bound dn>` | `TestDifferential389Oracle/whoami-bound`; CAND-20 bound case. |
| D14 | WhoAmI anonymous with anonymous access off | `inappropriateAuthentication(48)` | `success` + empty authzId | `TestDifferential389Oracle/whoami-anonymous`; CAND-20 anonymous case. |

The adjudication record (observed values, rationale, controlling tests)
is `docs/design/parity-delta-log.md` (T-150).

## 4. Excluded (not in M9)

| ID | Topic | Reason |
| --- | --- | --- |
| E1 | Replication, changelog, multi-master | LabLDAP is a single-instance lab. |
| E2 | SASL (GSSAPI, EXTERNAL, DIGEST-MD5, …) | No scenario field requires it. Adding it is a new ADR. |
| E3 | RFC 3062 Password Modify extended op | T-115 uses `userPassword` replace. |
| E4 | Roles, CoS, views, POSIX, winsync, DNA, linked attributes, etc. | Unused plugin families. |
| E5 | Active Directory / Samba emulation | README non-goal. |
| E6 | Arbitrary 389 ACI features the compiler does not emit | See C8. |
| E7 | `dsidm` / `dsctl` compatibility CLI on native | Native has no 389 tools. |
| E8 | Indexes as a scenario/plan object | `EnginePlan` has no indexes field. |

## 5. Parity harness rules (T-147+)

1. One scenario fixture compiled once; applied to a fresh 389 instance and a fresh native instance.
2. For each Contract case: perform the operation through **direct LDAP** (independent client) and, where listed, through the control plane against each engine.
3. Compare: result code, normalized DN set, normalized attribute sets (secrets stripped), bind success boolean, `memberOf` sets, enablement, lockout.
4. Do not compare: `vendorVersion`, password hashes, `createTimestamp` clock values beyond “present and RFC3339-ish”, backend CNs.
5. Failures attach redacted engine logs. Secret scan of the parity run must pass.
6. `make test-parity` runs both engines. `make test-integration` remains 389-only until T-148 parametrizes it.
7. A living **delta ledger** (section 3 of this file, plus the adjudication record `docs/design/parity-delta-log.md` created by T-150) records observed-but-accepted differences with the test name that proves them.

## 6. Implementation notes for agents

- Package and import rules: [ADR-0009](../adr/0009-native-engine-topology-and-storage.md) §Package layout.
- Interface skeletons land in T-122 **before** parallel work. Do not invent a second `Store` or `Codec` API in a feature branch.
- Reuse `internal/config` ACI golden text as the ACI parser corpus (T-138).
- Reuse `internal/config` DN helpers; do not fork DN canonicalization.
- Fuzz targets: BER, filter, DN, ACI (extend existing `internal/config` fuzz where the parser lives in ldapserver).
- Logging: same redaction rules as `AGENTS.md`. Bind passwords, DM password, hashes never log.
- Definition of done for any Contract feature: 389 test still green **and** native test green **and** a parity case, unless the task is native-only infrastructure (codec unit tests) explicitly marked as such.

## 7. Amendment log

| Date | Change |
| --- | --- |
| 2026-08-15 | Initial contract (`labldap.parity.v1`) accepted with ADR-0008 / ADR-0009. |
| 2026-08-15 | Wave 1 (T-125–T-128) recorded Delta **candidates** below; none are promoted to section 3 until adjudicated against the 389 oracle in T-147/T-150. |
| 2026-08-15 | T-150 differential harness (`internal/ldapserver/differential_test.go`) adjudicated CAND-1, CAND-3, CAND-4, CAND-5, CAND-18, CAND-20 against the pinned 389 oracle: CAND-3 resolved as Contract; the rest promoted to section 3 as D8–D14 (with newly observed D10). Record: `docs/design/parity-delta-log.md`. |
| 2026-10-03 | CAND-29 (ModifyDN deleteoldrdn equality) resolved as Contract against the pinned 389 image; CAND-30 (case-only rename 68 vs 0) recorded as open. |
| 2026-10-04 | C6 filter attribute descriptions (subtype/option matching, OID and second-descriptor resolution, filter-leaf search identity) aligned with the pinned 389 image; Compare difference recorded as D34; CAND-31 (filter leaf on a non-attribute literal targetattr) and CAND-32 (targetattr list syntax) recorded as open (both resolved as Contract later the same day). |
| 2026-10-04 | CAND-31 and CAND-32 resolved as Contract (owner: "We keep parity"): search result visibility needs read on a non-operational attribute the entry holds; `targetattr` lists use `\|\|` and accept numeric OIDs, compared literally. CAND-33 (targetattr schema check), CAND-34 (options in targetattr) and CAND-35 (entry-level search check and attribute-scoped deny) recorded as open. |
| 2026-10-04 | CAND-33, CAND-34 and CAND-35 resolved as Contract (owner: "Do the fixes"; oracle probes 16-20): `targetattr` names are checked against the pinned 389 schema, options in `targetattr` cover only descriptions carrying them, an omitted `targetattr` targets no attribute, and search and Modify have no entry-level check. ACI identities resolve second descriptors (`userid` as `uid`) and an empty filter option matches nothing (#28 review notes, probe 20). CAND-36 (modrdn entry gates), CAND-37 (`targetattr!="*"`) and CAND-38 (absolute filters) recorded as open. D36 recorded: 389 reuses a connection's earlier ACL decision for the plain type when it checks an option-bearing description (probe 24); native always gives the fresh-connection answer. |
| 2026-10-04 | CAND-36, CAND-37 and CAND-38 resolved as Contract with the DSL list follow-up (owner: "we keep parity"; oracle probes 25-29): same-parent modrdn uses 389's gates and result-code order, a no-op rename succeeds, `"*"` is accepted in `targetattr` lists and after `!=`, absolute filters are rejected with protocolError(2), and DSL attribute lists compile to one 389 list. CAND-39 (cross-parent moves need 389's `moddn` right) recorded as open; CAND-30 stays open. |
| 2026-10-04 | CAND-39 and CAND-30 (case-only half) resolved as Contract (owner, oracle probes 30-34): native supports `moddn` (moves need it on the new superior), the runtime ACIs grant it under people, groups and each additional suffix, moves between managed suffixes are 71, case-only renames respell the DN; CAND-40 (internal spaces) split off; D37 and D38 recorded. |

### Delta candidates observed in Wave 1 (pending adjudication, T-147/T-150)

| Ref | Topic | Native behavior (as implemented) | 389 expectation | Provenance |
| --- | --- | --- | --- | --- |
| ~~CAND-1~~ → D9 | Anonymous-bind-disabled result code | `unwillingToPerform(53)` | Oracle 2026-08-15: 389 returns `inappropriateAuthentication(48)` (contrary to the earlier note); accepted as D9 | T-126 `op_bind.go` |
| CAND-2 | `approxMatch` filter | Folds to equality until T-131 matching rules | 389 applies real approx rules | T-127 `filter_eval.go` |
| ~~CAND-3~~ → Contract | Modify delete-of-missing / replace-of-missing attribute | Strict RFC 4511 (`noSuchAttribute`) | Oracle 2026-08-15: 389 agrees (`noSuchAttribute`); resolved as Contract, harness step untagged | T-128 `op_write.go` |
| ~~CAND-4~~ → D11 | Cross/out-of-suffix ModifyDN | `unwillingToPerform(53)` | Oracle 2026-08-15 confirmed `affectsMultipleDSAs(71)`; accepted as D11 | T-128 `op_write.go` |
| ~~CAND-5~~ → D12 | Paged-results cookie integrity | HMAC-signed since T-140, fails closed | Oracle 2026-08-15: 389 has no cookie integrity (tamper → success); accepted as D12 | T-127 `op_search.go`, T-140 `ctrl_paged.go` |

When adjudicated, each moves into section 3 (accepted Delta) with the test name that proves the difference, or is fixed to match the oracle (Contract).

| ~~CAND-6~~ → Contract | ModifyDN rename into own subtree | rejects with `unwillingToPerform(53)` without changing the tree, including case variants | 389 also rejects with 53 | resolved 2026-10-03; `TestDualEngineParity`, `TestNativeReviewDirectoryRegressions` |
| ~~CAND-29~~ → Contract | ModifyDN `deleteoldrdn` with a rule-equal old/new RDN value | removes old RDN value(s) by the equality rule, then appends the new RDN value unless an equal value remains (a respelled or differently cased RDN no longer empties the naming attribute; a pure move with deleteoldrdn stores the request spelling last) | 389 observed identical value lists for respell, pure move, multi-valued equal and keep-old cases | resolved 2026-10-03; `TestModifyDNDeleteOldRDNEquality`, `TestNativeReviewDirectoryRegressions/rename-deleteoldrdn-equality`, `TestDualEngineParity` (C1 `modifydn-semantics`: whitespace respell-with-move, which discriminates the fix, and multi-valued-equal rename) |
| ~~CAND-30~~ | Case-only ModifyDN (`uid=keeper` → `uid=Keeper`) | was `entryAlreadyExists(68)` | 389 `success(0)`, respells the DN (probes 28, 30, 31, 33, 34) | resolved 2026-10-04 as Contract (owner: case-only renames succeed and respell, as on 389); the internal-space half moved to CAND-40; `TestModDNCaseOnlyMatchesOracle`, `TestModDNMatchesOracle` |
| CAND-40 | DNs differing only in internal spaces (`uid=a b` vs `uid=a  b`); suffix value spelled in another case in a ModifyDN request (`...,DC=EXAMPLE,dc=test`) | distinct entries (DN identity folds case but not spaces); the suffix-case request is unwillingToPerform(53) because the managed-suffix checks compare RDNs exactly | 389 returns space-normalised DNs (local probe 2026-10-03; PR #19 comment); 389 accepts the suffix-case request and stores that spelling (probe 30 `dm parentcase`) | open; split from CAND-30; fold-aware fix pending |
| ~~CAND-31~~ → Contract | Filter leaf on a non-attribute literal `targetattr` (`targetattr="userid"`, subject searching `(!(userid;x-test=bobtag))`) | the leaf is allowed (literal `userid`) and its NOT is True, but the entry is not returned because the subject can read no attribute it holds (search result visibility, C8) | 389 returns no entries (probes 6, 8 and 10: the entry needs read on at least one non-operational attribute it holds) | resolved 2026-10-04 (owner: "We keep parity"); `TestSearchEntryVisibilityMatchesOracle`, `TestFilterLeafSearchIdentityMatchesOracle`, `TestDualEngineFilterAttributeDescriptionParity` |
| ~~CAND-32~~ → Contract | `targetattr` list syntax | accepts `\|\|`-separated lists (any spacing) and numeric-OID names, compared literally; rejects a single `\|` | 389 identical (probes 8, 10 and 11) | resolved 2026-10-04 (owner: "We keep parity"); `TestTargetAttrListsMatchOracle`, `TestSearchEntryVisibilityMatchesOracle`, `TestDualEngineFilterAttributeDescriptionParity` |
| ~~CAND-33~~ → Contract | `targetattr` names checked against the schema | rejects names outside the pinned 389 schema (embedded attribute types, aliases, OIDs, `-oid` placeholders; options unchecked): startup `invalid_aci`, DSL `unknown_attribute` | 389 rejects them with invalidSyntax(21) when the ACI is added (probes 16, 17, 19) | resolved 2026-10-04 (owner: "Do the fixes"); `TestTargetAttrSchemaCheckMatchesOracle`, `TestKnownMatchesOracle`, `TestACLAttributesMustExistIn389Schema` |
| ~~CAND-34~~ → Contract | Options inside `targetattr` (`"uid;x-test"`) | a name with options covers only descriptions carrying all of them; `uid;` covers nothing | 389 identical for filter leaves, reads, compares and writes (probes 12, 16, 18) | resolved 2026-10-04 (owner: "Do the fixes"); `TestTargetAttrOptionsAndEntryLevelSearchMatchOracle`, `TestTargetAttrOptionsMatchProbe12`, `TestACITargetAttrOptionsAndEntryLevel` |
| ~~CAND-35~~ → Contract | Entry-level search check with an attribute-scoped deny; omitted `targetattr` | no entry-level search or Modify check; an omitted `targetattr` targets no attribute (entry-level checks only) | 389 identical (probes 14, 16, 18, 19) | resolved 2026-10-04 (owner: "Do the fixes"); `TestTargetAttrOptionsAndEntryLevelSearchMatchOracle`, `TestACITargetAttrOptionsAndEntryLevel` |
| ~~CAND-36~~ → Contract | ModRDN entry-level gates and result-code order (same-parent renames) | write on the new (and with deleteoldrdn the old) RDN attribute on the old DN; only a deny-write without `targetattr` blocks at entry level; no add; missing source 50 for non-root (refined by CAND-39: 32 with `moddn` under the existence filter); 68 and 53 before the access check; a no-op rename is success | 389 identical (probes 25-29) | resolved 2026-10-04 (owner: "we keep parity"); `TestModifyDNRenameMatchesOracle`, `TestModifyDNOrderingMatchesOracle`, `TestModifyDNNoOpRename`, `TestACIModRDNStarListsAbsoluteFilters`, `TestDualEngineCand3638Parity` |
| ~~CAND-37~~ → Contract | `targetattr!="*"` and lists holding `"*"` | accepted; a negated list holding `"*"` covers no attribute, a positive one every attribute; entry-level add/delete still apply the ACI | 389 identical (probes 25, 26) | resolved 2026-10-04 (owner: "we keep parity"); `TestTargetAttrStarListsMatchOracle`, `TestACIModRDNStarListsAbsoluteFilters`, `TestDualEngineCand3638Parity` |
| ~~CAND-38~~ → Contract | Absolute true/false filters (`(&)`, `(\|)`, RFC 4526) | rejected with protocolError(2) "Bad search filter" for every subject and base, before controls; the connection stays open | 389 identical (probes 19, 25, 26, 28, 29) | resolved 2026-10-04 (owner: "we keep parity"); `TestAbsoluteFilterRejectedMatchesOracle`, `TestACIModRDNStarListsAbsoluteFilters`, `TestDualEngineCand3638Parity` |
| ~~CAND-39~~ | Cross-parent ModifyDN | was entry write + add gates on native | 389 needs `moddn` on the new superior (probes 26, 30-34) | resolved 2026-10-04 as Contract (owner option (b): native `moddn`, granted in the runtime ACIs); `TestModDNMatchesOracle`, `TestRESTMovesWithRuntimeGrant` |
| CAND-17 | groupdn membership scope | direct `member`/`uniqueMember` only, no nesting; group objectClass not required | confirm vs 389 | T-139 `aci_eval.go` |
| ~~CAND-18~~ → D12 | Paged-cookie tamper result code | `unwillingToPerform(53)`; cookie is HMAC-SHA256 (offset + base DN + scope + filter), per-server random secret | Oracle 2026-08-15: 389 accepts a tampered cookie (`success`); accepted as D12 | T-140 `ctrl_paged.go` |
| CAND-19 | Assertion control scope | Modify-only; critical assertion on non-Modify → `unavailableCriticalExtension`; `assertionFailed(122)` on mismatch | 389 assertion-on-Add / non-critical behavior unverified | T-141 `ctrl_assert.go`; adjudicate in T-147 |
| ~~CAND-20~~ → D13/D14 | WhoAmI authzid rendering | `dn:<dn>` with case-preserving `DN.String()`; present-but-empty value for anonymous | Oracle 2026-08-15: 389 renders `dn: <case-folded dn>` (D13) and, with anonymous access off, refuses the op with `inappropriateAuthentication(48)` (D14) | T-142 `ext_whoami.go` |

**Resolved:** ~~CAND-7~~ (supportedExtension advertised StartTLS/WhoAmI pre-handler) — both handlers now exist (T-133 StartTLS, T-142 WhoAmI); the Root DSE advertisement is truthful. CAND-7 is removed from the candidate set.
| CAND-8 | MAY-attribute allow-listing not enforced on writes | Only MUST enforced; 389 accepts marker attrs (destinationIndicator/owner on device) | Matches 389-observed | T-132 `schema_registry.go`; confirm vs oracle in T-147 |
| CAND-9 | Password-policy-violation writes (min length, history) | `unwillingToPerform(53)` via the plugin-abort path | 389 returns `constraintViolation(19)` | T-134 `password.go`; adjudicate in T-147 |
| CAND-10 | Lockout / expired-password bind failure code | `invalidCredentials(49)` | confirm 389's exact bind-path code | T-134 `password.go`; adjudicate in T-147 |
| CAND-11 | Re-setting the current password | Rejected as in-history (stricter) | 389 known to allow re-set in some paths | T-134 `password.go`; adjudicate in T-147 |
| CAND-12 | Empty groupOfNames after RI member removal | handling per 389-observed (groupOfNames cannot be empty) | 389-observed fail-or-keep | T-136 `refint.go`; confirm vs oracle in T-147 |
| CAND-13 | ACI evaluation order | Order-independent deny-wins | 389 never first-match/subtree-distance on the T-036 set | T-139 `aci_eval.go`; confirm vs oracle in T-147 |
| CAND-14 | `userPassword` read under `ou=people` | `runtime-people-write` (targetattr!=aci) grants it; suffix/marker deny it via `runtime-suffix-read` | pin 389's answer on a person entry | T-139; T-036 probes suffix/marker only |
| CAND-15 | self/all/anyone semantics | pre-bind = anonymous for `all`; `self` = bound DN vs target DN only | confirm vs 389 | T-139 `aci_eval.go` |
| CAND-16 | ACI target scope + entry-level attr | "at or under target DN", fold-correct; entry add/delete ignore `targetattr` | 389 add checks may differ for entries carrying `aci` | T-139 `aci_eval.go` |
| CAND-17 | groupdn membership scope | direct `member`/`uniqueMember` only, no nesting; group objectClass not required | confirm vs 389 | T-139 `aci_eval.go` |
