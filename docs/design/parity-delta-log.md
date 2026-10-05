# Native-Engine Parity Delta Log

Status: living ledger (T-150). Companion to
[native-engine-parity-contract.md](native-engine-parity-contract.md): the
contract's section 3 defines the Delta tier; this log is the adjudication
record — every accepted Delta with the observed behavior on each engine,
the rationale for accepting the difference, and the controlling test that
keeps it stable.

A difference between engines is **not** a Delta until it is adjudicated.
Undecided divergences found by the differential harness
(`internal/ldapserver/differential_test.go`) or the parity harness
(`test/parity/`) fail the build; they are fixed (native moves to Contract
behavior) or recorded here with evidence.

## Recording rules

1. Each Delta gets the next free `D<number>`; numbers are never reused,
   even if a Delta is later resolved (strike it instead of deleting).
2. Evidence is the exact test and step that observes both engines, plus
   the observed outcomes. "Observed" means run against the pinned 389
   image (`deploy/docker/dirsrv.digest`), currently 389-Directory 2.4.6.
3. The controlling test fails if either engine's behavior changes, so a
   resolved Delta is detected by the harness itself ("engines agree …
   delta may be resolved"), not by remembering to edit this file.
4. T-147's machine-readable ledger (`test/parity/delta-ledger.json`,
   schema `labldap.parity.v1`, golden file regenerated via
   `PARITY_UPDATE_LEDGER=1`) is generated from the same observations;
   this document is the human narrative. The two must not disagree — if
   they do, this log wins per the repository source-of-truth hierarchy
   and the JSON is regenerated. T-147's ledger is now generated; the
   D8–D14 adjudications from this task's differential harness are
   consistent with it (T-147 records D8 as its `CAND-21`, D9 as
   `CAND-1`, D11 as `CAND-4`, D12 as `CAND-5`/`CAND-18`, and D13/D14 as
   `CAND-20`), and the sections below fold in the additional candidates
   T-147's oracle probes adjudicated.

## Accepted Deltas

D1–D7 are design-time acceptances defined in the contract (section 3).
D8 onward are adjudicated against the running oracle.

| ID | Topic | 389 (observed) | Native (observed) | Rationale | Controlling test |
| --- | --- | --- | --- | --- | --- |
| D1 | Vendor identity | `389-Directory/2.4.6 …` | distinct `vendorName`/`engineVendor` | Honest advertisement; contract D1 | contract capabilities tests |
| D2 | Admin plane | `cn=config`, `dsconf`, `nsslapd-*` | none; plan applied at start | Native has no 389 tools (contract D2) | bootstrap reconciler tests |
| D3 | Password hash encoding | 389 wire form | same schemes, different blobs | Never compare hashes; bind with plaintext | bind tests |
| D4 | On-disk format | `/data` nsslapd db | bbolt `/data/labldapd.bolt` | Storage is engine-owned | lifecycle tests |
| D5 | Backend name | `userroot` | no backend CN | Suffix, not backend, is the contract | bootstrap tests |
| D6 | Root DSE / entry operational extras | 389 emits `entrydn`, `dsentrydn`, `entryid`, `parentid`, `nsuniqueid` on `+` | honest advertisement; omits 389-specific attrs | Capability inspection is measured, not name-assumed | `TestDifferential389Oracle/search-base-attrs` (strips the 389 set) |
| D7 | Assertion absence path | pinned 389 build does not advertise or implement RFC 4528; critical requests fail 12 and non-critical requests are ignored | must advertise and honor | Safety floor | native assertion atomicity tests; CAND-25/CAND-26 |
| D8 | Bind with malformed DN | `invalidDNSyntax(34)` | `invalidCredentials(49)` | Fail-closed without revealing DN-shape validation to unauthenticated callers | `TestDifferential389Oracle/bind-malformed-dn` |
| D9 | Anonymous bind while disabled | `inappropriateAuthentication(48)` | `unwillingToPerform(53)` | Both deny; code choice differs (CAND-1 adjudicated 2026-08-15; supersedes the earlier "389 observed 53" note) | `TestDifferential389Oracle/anon-bind-disabled` |
| D10 | LDAPv2 bind attempt | `invalidCredentials(49)` | `protocolError(2)` | Native is strict RFC 4511 §4.2; 389 folds version rejection into credential failure | `TestDifferential389Oracle/bind-version-2` |
| D11 | ModifyDN with a `newSuperior` outside every managed suffix (a move between managed suffixes is 71 on both engines since CAND-39) | `affectsMultipleDSAs(71)` | `unwillingToPerform(53)` | Single-suffix native engine has no DSA concept (CAND-4 adjudicated 2026-08-15) | `TestDifferential389Oracle/modifydn-cross-suffix` |
| D12 | Paged-results cookie tamper | accepts tampered cookie, `success(0)` — no integrity protection | HMAC-SHA256 cookie (offset + base DN + scope + filter) fails closed with `unwillingToPerform(53)` | Native is deliberately stricter (T-140); 389's cookie is an opaque connection-slot index (CAND-5/CAND-18 adjudicated 2026-08-15) | `TestDifferential389Oracle/paged-tampered-cookie` |
| D13 | WhoAmI bound authzId rendering | `dn: cn=directory manager` (space after `dn:`, case-folded) | `dn:cn=Directory Manager` (no space, as-bound case) | Both are valid RFC 4532 authzIds; rendering only (CAND-20 bound case, adjudicated 2026-08-15) | `TestDifferential389Oracle/whoami-bound` |
| D14 | WhoAmI anonymous, anonymous access disabled | `inappropriateAuthentication(48)` — the op itself is refused | `success(0)` with present-empty responseValue | 389 gates the extended op on the anonymous-access switch; native answers truthfully per RFC 4532 (CAND-20 anonymous case, adjudicated 2026-08-15) | `TestDifferential389Oracle/whoami-anonymous` |
| D31 | Optioned `userPassword` storage (direct LDAP write of an attribute-option spelling, e.g. `userPassword;lang-en`) | stored as written (plaintext); bind with it fails | hashed with the configured scheme; pre-hashed values pass through as for D3; bind with it fails. Because the stored value is a hash, deleting a specific plaintext value, compare, and equality filters against the plaintext also differ from 389 | Native never keeps credential material in plaintext. The control plane rejects these spellings on both engines and redacts them on read, so only a principal with LDAP write access outside the control plane (Directory Manager, the runtime account, or an operator ACI) reaches storage | `TestPasswordOptionSpellingsAreRejectedAndRedacted` step (d) (`test/integration/dirsrv`, both engines). The `2.5.4.35` OID spelling over direct LDAP is not covered by this row and is not yet compared |
| D34 | Compare with attribute descriptions (probe 5, pinned image f2851654; `test/parity/testdata/filter-attr-oracle-probes.txt`) | subtype semantics for the primary name: `uid:bobtag`, `uid;x-test:bobtag`, `description:hello`, `description;lang-en:hello` (value stored as `description;lang-en`) → `compareTrue(6)`; `uid;x-test:bob` → `compareFalse(5)`; no alias or OID resolution: `userid:bob`, the uid OID, `userid;x-test`, `OID;x-test`, `2.5.4.13:hello`, `description;lang-fr:hello` → `noSuchAttribute(16)` | matches the stored name exactly: `compareTrue(6)` for `uid:bob`, `cn:BOB`, `uid;x-test:bobtag`, `description;lang-en:hello`; `compareFalse(5)` for every other row, including `uid:bobtag` and `description:hello` (389: 6) and the 389 `noSuchAttribute` rows (overlaps D25) | Search filters follow 389 (contract C6); Compare keeps exact stored-name matching until a follow-up aligns it. The ACI identity for compare, read and write now resolves second descriptors (`userid` is checked as `uid`, #29); only the value match stays exact | `TestDualEngineFilterAttributeDescriptionParity` compare step (`test/parity`) asserts each engine's column, so a change on either side fails it |
| D35 | Entry-API delete of a second-descriptor spelling (`{op: delete, name: rfc822Mailbox}`) | the alias is the type: deletes `mail` values | deletes a legacy attribute stored under that spelling and option set (direct LDAP write, D17; a value delete only when that row holds the values) and leaves `mail` untouched; without one, an optioned spelling (`rfc822Mailbox;lang-en`) deletes the matching optioned primary (`mail;lang-en`, which is what add/replace of that spelling wrote) and a bare spelling answers `noSuchAttribute(16)` (HTTP 409, field `attribute`/`conflict`) with `mail` untouched. Replace/add of an alias write the primary type on both engines | Entry-update delete of a bare alias keeps the client's spelling (owner instruction, 2026-10-04); an optioned alias with no stored alias row resolves to the optioned primary its add wrote so legacy native values stay removable without wiping the real attribute; normal clients never send alias names (user view and console use primary names, and the console blocks replace/add of every alias name and offers delete only for a row stored under the alias spelling). Resolvable when D17 is retired (native rejects unknown attributes) | `TestLegacyAliasAttributeDelete`, `TestOptionedAliasDeleteRoundTrip` (`test/integration/dirsrv`, both engines) |
| D36 | ACI decisions for option-bearing attribute descriptions on a reused connection (probes 21-24, pinned image f2851654) | the answer depends on connection history: after a search evaluated the plain type (`(uid=fa_bob)`), a later `(uid;x-test=...)` on the same connection reuses that decision, so `targetattr="uid;x-test"` stops matching and `targetattr!="uid;x-test"` or a deny on `uid;x-test` stops excluding; on a fresh connection the option rule applies (CAND-34) | always the fresh-connection answer (subset rule, CAND-34) | A per-connection ACL cache artefact in 389; a history-dependent decision is not reproducible, and the fresh answer is the one 389 gives first | `TestACITargetAttrOptionsAndEntryLevel` (D36 rows accept either answer on 389, since the reuse is not reliable, and pin native to the fresh one; other rows use fresh connections), `TestTargetAttrOptionsAndEntryLevelSearchMatchOracle` |
| D37 | Attribute-type case in written DNs (probes 30, 33, 34) | keeps the request's attribute-type case in the stored DN (`UID=e29,ou=MixCase,...`, `uid=Keeper,OU=SRC,DC=EXAMPLE,...`) | lowercases attribute types in every DN it parses and stores (contract §2 canonical DN rules); values keep their case | DN identity is case-insensitive for types on both engines; only the returned spelling differs | `TestModDNSpellingMatchesOracle` (rows use lowercase types) |
| D38 | `target_from` / `target_to` ACI keywords (probe 30) | supported (source and destination filters for `moddn`) | not supported: a raw ACI using them fails native startup (`invalid_aci`) | LabLDAP never emits them; fail-closed grammar (C8) | `TestParseACITextA` rejection rows |

D35 covers entry-update writes only. Native search filters resolve second descriptors as 389 does (contract C6, #28): `(rfc822Mailbox=x)` matches `mail` values, and a stored legacy `rfc822Mailbox` row also resolves to `mail`, so `(mail=x)` matches it too. Compare (D34) and search attribute lists still match the attribute name literally and do not resolve aliases.

## Resolved candidates (Contract, not Delta)

These were adjudicated and the engines **agree**; the behavior is Contract
and the harness step runs untagged, so a future regression in either
engine fails as an undecided divergence.

| Ref | Topic | Agreed behavior | Evidence |
| --- | --- | --- | --- |
| CAND-3 | Modify delete of a missing attribute | `noSuchAttribute(16)` on both engines | `TestDifferential389Oracle/modify-delete-missing-attr` (2026-08-15); `delta-ledger.json` verdict `match` |
| CAND-7 | Root DSE `supportedExtension` advertising handlers that did not exist yet | Both handlers exist (T-133 StartTLS, T-142 WhoAmI) | contract note, resolved in Wave 1; `delta-ledger.json` verdict `match` |
| CAND-12 | Empty groupOfNames after RI member removal | member removed, empty group retained | `delta-ledger.json` verdict `match` |
| CAND-13 | ACI evaluation order | order-independent deny-wins on the T-036 set | `delta-ledger.json` verdict `match` |
| CAND-14 | `userPassword` read under `ou=people` as runtime | granted by `runtime-people-write` on a person entry | `delta-ledger.json` verdict `match` |
| CAND-16 | ACI entry-level add/delete `targetattr` scope | add/delete ignore `targetattr`; missing entry → `noSuchObject(32)` | `delta-ledger.json` verdict `match` |
| CAND-31 | Search result visibility (filter leaf on a literal `targetattr="userid"`) | an entry is returned only if the subject may read at least one non-operational attribute it holds (389 usage); the CAND-31 row returns none on both engines | oracle probes 6, 8, 10, 12, 13, 15 (`test/parity/testdata/filter-attr-oracle-probes.txt`); `TestDualEngineFilterAttributeDescriptionParity`, `TestACIEntryVisibilityAndTargetAttrLists` (2026-10-04, owner: "We keep parity") |
| CAND-32 | `targetattr` list syntax | `\|\|`-separated lists and numeric-OID names accepted and compared literally; single `\|` rejected | oracle probes 8, 10, 11, 14; `TestTargetAttrListsMatchOracle`, `TestDualEngineFilterAttributeDescriptionParity`, `TestACIEntryVisibilityAndTargetAttrLists` (2026-10-04) |
| CAND-33 | `targetattr` names checked against the schema | names outside the pinned 389 schema are rejected (389: invalidSyntax(21) on add; native: startup `invalid_aci`, DSL `unknown_attribute`); options unchecked | oracle probes 16, 17, 19; `TestTargetAttrSchemaCheckMatchesOracle`, `TestKnownMatchesOracle`, `TestACLAttributesMustExistIn389Schema`, `TestTargetAttrUnknownNameRejected` (2026-10-04) |
| CAND-34 | Options inside `targetattr` | a name with options covers only descriptions carrying all of them; `uid;` covers nothing | oracle probes 12, 16, 18; `TestTargetAttrOptionsAndEntryLevelSearchMatchOracle`, `TestTargetAttrOptionsMatchProbe12`, `TestCodeSweepEdgeCases`, `TestACITargetAttrOptionsAndEntryLevel`, `TestDualEngineFilterAttributeDescriptionParity` `fattr35` rows (2026-10-04) |
| CAND-35 | Entry-level search/Modify check; omitted `targetattr` | no entry-level search or Modify check; an omitted `targetattr` targets no attribute; Modify checks every change before the entry read and assertion | oracle probes 14, 16, 18, 19; `TestTargetAttrOptionsAndEntryLevelSearchMatchOracle`, `TestACITargetAttrOptionsAndEntryLevel`, `TestDualEngineFilterAttributeDescriptionParity` `fattr35` rows (2026-10-04) |
| CAND-36 | ModRDN gates and result-code order (same-parent renames) | write on the new (and with deleteoldrdn the old) RDN attribute on the old DN; only a deny-write without `targetattr` blocks at entry level; no add; missing source 50 for non-root (refined by CAND-39: 32 with `moddn` under the existence filter); 68/53 before the access check; no-op rename succeeds | oracle probes 25-29; `TestModifyDNRenameMatchesOracle`, `TestModifyDNOrderingMatchesOracle`, `TestModifyDNNoOpRename`, `TestACIModRDNStarListsAbsoluteFilters`, `TestDualEngineCand3638Parity` (2026-10-04) |
| CAND-37 | `targetattr!="*"` and lists holding `"*"` | accepted; negated star list covers no attribute, positive one every attribute; entry-level add/delete still apply | oracle probes 25, 26; `TestTargetAttrStarListsMatchOracle`, `TestACIModRDNStarListsAbsoluteFilters`, `TestDualEngineCand3638Parity` (2026-10-04) |
| CAND-38 | Absolute filters `(&)`, `(\|)` | protocolError(2) "Bad search filter" for every subject and base, before controls | oracle probes 19, 25, 26, 28, 29; `TestAbsoluteFilterRejectedMatchesOracle`, `TestACIModRDNStarListsAbsoluteFilters`, `TestDualEngineCand3638Parity` (2026-10-04) |
| CAND-39 | Cross-parent ModifyDN | `moddn` on the new superior at entry level plus the rename gates on the old DN; no add/delete; missing source/superior 32 only with `moddn` there (existence filter), else 50; moves between managed suffixes 71; runtime ACIs grant `moddn` under people, groups and each additional suffix | oracle probes 26, 30-34; `TestModDNMatchesOracle`, `TestRESTMovesWithRuntimeGrant`, `TestModDNMovesMatchOracle`, `TestModDNExistenceMatchesOracle` (2026-10-04) |
| CAND-30 | Case-only ModifyDN | succeeds with the rename gates and respells the DN (children follow); member values and memberOf left as written; new DN uses the request parent spelling (rename) or the stored superior spelling (move) | oracle probes 28, 30, 31, 33, 34; `TestModDNCaseOnlyMatchesOracle`, `TestModDNSpellingMatchesOracle`, `TestModDNPluginsMatchOracle` (2026-10-04); the internal-space half stays open as CAND-40 |
| CAND-19 | Assertion control scope on non-Modify ops | `unavailableCriticalExtension(12)` on critical non-Modify; `assertionFailed(122)` on mismatch | `delta-ledger.json` verdict `match` |

## Deltas adjudicated by T-147's oracle probes

The differential harness adjudicated D8–D14. T-147's parity probes
(`test/parity/probes.go`, recorded in `test/parity/delta-ledger.json`)
adjudicated the remaining Wave-1 candidates against the same pinned 389
oracle. Each `delta` verdict below is an accepted engine difference; the
controlling evidence is the named probe plus the ledger's `oracle` /
`native` outcome columns. D-numbers continue the sequence from D14.

| Ref | Topic | 389 (observed) | Native (observed) | Verdict |
| --- | --- | --- | --- | --- |
| D15 (CAND-2) | `approxMatch` filter semantics | real approx matching, extra step returns the entry | folds to equality (one step returns nothing) | delta |
| ~~D16 (CAND-6)~~ | ModifyDN rename into own subtree | rejects, `unwillingToPerform(53)`; subtree stays put | now rejects, `unwillingToPerform(53)`; subtree stays put | resolved 2026-10-03; `TestDualEngineParity` regenerated ledger |
| D17 (CAND-8) | Schema MAY / unknown-attribute enforcement on writes | rejects MAY-violation adds with `objectClassViolation(65)`; unknown attrs `noSuchObject(32)` paths | accepts marker attrs (`destinationIndicator`/`owner` on device) and unknown attrs, `success(0)` | delta |
| D18 (CAND-9) | Password-policy-violation write code | `constraintViolation(19)` | `unwillingToPerform(53)` (plugin-abort path) | delta |
| D19 (CAND-10) | Lockout bind failure code | 5th failure → `constraintViolation(19)`; 389 stamps `accountUnlockTime`/`nsUniqueId`/`passwordRetryCount` | 5th failure → `invalidCredentials(49)`; native stamps `pwdAccountLockedTime`/`pwdChangedTime` | delta |
| D20 (CAND-11) | Re-setting the current password | allowed (`success`) | rejected as in-history, `unwillingToPerform(53)` | delta |
| D21 (CAND-15) | self/all/anyone bind-rule semantics | anonymous under `anyone` denied `inappropriateAuthentication(48)` when anonymous is off | anonymous read of `ou=probe-anyone` allowed, `success(0)` | delta |
| D22 (CAND-17) | groupdn membership scope (nesting) | nested groupdn grant resolves, leaf readable both times | second groupdn read returns empty (no nesting) | delta |
| D23 (CAND-21) | Malformed-DN bind result code | `invalidDNSyntax(34)` | `invalidCredentials(49)` | delta (same divergence as D8; T-147's ledger records it as `CAND-21`) |
| D24 (CAND-22) | Pre-bind Root DSE read with anonymous off | anonymous op refused `inappropriateAuthentication(48)` | pre-bind Root DSE read allowed, `success(0)` | delta |
| D25 (CAND-23) | Compare against an absent attribute | `noSuchAttribute(16)` | `compareFalse(5)` | delta |
| D26 (CAND-24) | memberOf auxiliary object class add/retract | adds and **retracts** `nsMemberOf` objectclass with membership | adds `nsMemberOf` on grant but does not retract it on removal | delta |
| D27 (CAND-25) | `supportedLDAPVersion` advertises v2 | `2, 3` | `3` only | delta |
| D28 (CAND-26) | Critical passing assertion on Modify | `unavailableCriticalExtension(12)`; asserts value `assert-v4` | honored, `success(0)`; asserts value `assert-v5` | delta |
| D29 (CAND-27) | DM password reset vs history policy | DM reset bypasses history, `success(0)` throughout | DM reset of an in-history password rejected, `unwillingToPerform(53)` | delta |
| D30 (CAND-28) | Subschema publishes `pwdAccountLockedTime` | publishes only `nsAccountLock` | publishes `nsAccountLock` **and** `pwdAccountLockedTime` | delta |

## How the differential harness uses this log

`internal/ldapserver/differential_test.go` drives one scripted LDAP
operation sequence against an in-process native server and — under
`LABLDAP_DIFF_389=1` with Docker and the pinned image — against the 389
oracle. Each step is tagged with the Delta ID that excuses its known
divergence; an untagged divergence fails the test with the message
pointing here. A tagged step whose engines have converged logs
"delta may be resolved" so the log entry can be struck.

The T-147 parity harness (`test/parity/compare_test.go`,
`-tags integration`) independently re-adjudicates every candidate and
rewrites `test/parity/delta-ledger.json` only under
`PARITY_UPDATE_LEDGER=1`; drift in either engine's observed behavior
fails that run.

## Review hardening (2026-10-03)

D16 is resolved: refusing moves beneath the source (including case variants)
prevents detached directory trees. The compiler-subset search policy now checks
each filter attribute. Denied assertions evaluate Undefined, including under
NOT; an authorized OR branch can still match. The same check protects native
RFC 4528 assertions (D7). Exact size limits succeed when no additional matching
entry exists. Native bbolt search traverses lazily so server limits stop decoding
before the entire subtree is materialized. Safe `uid`, `cn`, and `objectClass`
equality terms (standalone or required AND branches) stream indexed candidates;
DN-valued predicates retain traversal fallback pending Unicode-fold parity.

DN-key format version 2 rebuilds DN, child and equality indexes atomically from
stored entries on reopen. Invalid or duplicate stored DNs fail startup with a
static diagnostic, without committing a partial migration. Plain DNs keep their
keys; escaped values now retain structural boundaries. Operators should retain
a backup before downgrading an escaped-DN database to older binaries.
