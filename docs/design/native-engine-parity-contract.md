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

Message ID correlation, protocolOp tagging, and LDAPResult codes used by the control plane (`success`, `operationsError`, `protocolError`, `authMethodNotSupported`, `strongAuthRequired`, `noSuchObject`, `aliasProblem` unused, `invalidDNSyntax`, `insufficientAccessRights`, `busy`, `unavailable`, `unwillingToPerform`, `constraintViolation`, `entryAlreadyExists`, `invalidCredentials`, `inappropriateAuthentication`, `objectClassViolation`, `namingViolation`, `notAllowedOnNonLeaf`, `affectsMultipleDSAs` unused, `sizeLimitExceeded`, `timeLimitExceeded`, `adminLimitExceeded`, `unavailableCriticalExtension`, `confidentialityRequired`) are Contract where the product maps them (`internal/directory/ldapclient/errors.go`).

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

### C7. Groups, memberOf, referential integrity

- Forward membership is `groupOfNames` `member` (full DN).
- `memberOf` is derived. Membership add/remove/replace updates `memberOf` before the LDAP result returns (389 MemberOf plugin with fixup). Native: same-commit write-path plugin plus a fixup equivalent for bootstrap/reset.
- Nested groups follow `spec.directory.nestedGroups`.
- User (or group) delete repairs `member` references (referential integrity, update-delay 0, suffix-scoped). 389 observed: `test/integration/dirsrv/plugins_test.go`.

### C8. Access control

Native must evaluate the ACI **text the LabLDAP compiler already emits**, including golden fixtures under `internal/config` and `internal/config/testdata/runtime-acis.txt`.

Supported grammar (compiler subset):

```text
(target="ldap:///<dn>")
(targetattr="<attr>" | "*" | targetattr!="<attr>")
(version 3.0; acl "<name>"; allow (<perm>,...) <who>;)
```

| Clause | Contract |
| --- | --- |
| `target` | Entry is that DN or a descendant. |
| `targetattr` / `targetattr!` | Attribute allow or deny. |
| Permissions | `read`, `search`, `compare`, `add`, `delete`, `write` as emitted. |
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
| D11 | ModifyDN with out-of-suffix `newSuperior` | `affectsMultipleDSAs(71)` | `unwillingToPerform(53)` | `TestDifferential389Oracle/modifydn-cross-suffix`; CAND-4 adjudicated 2026-08-15. |
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

### Delta candidates observed in Wave 1 (pending adjudication, T-147/T-150)

| Ref | Topic | Native behavior (as implemented) | 389 expectation | Provenance |
| --- | --- | --- | --- | --- |
| ~~CAND-1~~ → D9 | Anonymous-bind-disabled result code | `unwillingToPerform(53)` | Oracle 2026-08-15: 389 returns `inappropriateAuthentication(48)` (contrary to the earlier note); accepted as D9 | T-126 `op_bind.go` |
| CAND-2 | `approxMatch` filter | Folds to equality until T-131 matching rules | 389 applies real approx rules | T-127 `filter_eval.go` |
| ~~CAND-3~~ → Contract | Modify delete-of-missing / replace-of-missing attribute | Strict RFC 4511 (`noSuchAttribute`) | Oracle 2026-08-15: 389 agrees (`noSuchAttribute`); resolved as Contract, harness step untagged | T-128 `op_write.go` |
| ~~CAND-4~~ → D11 | Cross/out-of-suffix ModifyDN | `unwillingToPerform(53)` | Oracle 2026-08-15 confirmed `affectsMultipleDSAs(71)`; accepted as D11 | T-128 `op_write.go` |
| ~~CAND-5~~ → D12 | Paged-results cookie integrity | HMAC-signed since T-140, fails closed | Oracle 2026-08-15: 389 has no cookie integrity (tamper → success); accepted as D12 | T-127 `op_search.go`, T-140 `ctrl_paged.go` |

When adjudicated, each moves into section 3 (accepted Delta) with the test name that proves the difference, or is fixed to match the oracle (Contract).

| CAND-6 | ModifyDN rename into own subtree | bbolt store allows it; index-based Subtree walks can detach the subtree (no store sentinel exists) — needs a dispatch guard | 389 rejects (LDAP-illegal) | T-129 `store.go`; guard belongs in ModifyDN dispatch (T-143/T-144 hardening) |
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
