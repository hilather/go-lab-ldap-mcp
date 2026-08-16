# Native-Engine Parity Delta Log

Status: living ledger (T-150). Companion to
[native-engine-parity-contract.md](https://github.com/hilather/go-lab-ldap-mcp/blob/main/docs/design/native-engine-parity-contract.md):
the contract's section 3 defines the Delta tier; this log is the
adjudication record — every accepted Delta with the observed behavior on
each engine, the rationale for accepting the difference, and the
controlling test that keeps it stable.

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
4. Observation source of truth is T-147's machine-readable ledger
   ([`test/parity/delta-ledger.json`](https://github.com/hilather/go-lab-ldap-mcp/blob/main/test/parity/delta-ledger.json),
   schema `labldap.parity.v1`, golden file regenerated via
   `PARITY_UPDATE_LEDGER=1`) — the structured `oracle` / `native`
   outcome columns. Probe *code* and step comments in
   [`test/parity/probes.go`](https://github.com/hilather/go-lab-ldap-mcp/blob/main/test/parity/probes.go)
   may narrate those steps only when they do not contradict the JSON;
   if a comment disagrees, the JSON wins. This document is the human
   narrative. If it disagrees with the JSON, the JSON wins and this log
   is corrected. (2026-08-16: D7 claimed 389 honors RFC 4528, D26
   swapped the engines, and D20 claimed 389 allows current-password
   re-set; those sentences were false relative to the ledger and are
   corrected below.) T-147's ledger is generated; D8–D14
   from the differential harness map as `CAND-21` / `CAND-1` / `CAND-4`
   / `CAND-5`+`CAND-18` / `CAND-20`; D15–D30 are the T-147 probe
   promotions in the table below and in contract section 3.

## Accepted Deltas

D1–D7 are design-time acceptances defined in the contract (section 3).
D8 onward are adjudicated against the running oracle. D15–D30 were
promoted into contract §3 on 2026-08-16 from the machine ledger.

| ID | Topic | 389 (observed) | Native (observed) | Rationale | Controlling test |
| --- | --- | --- | --- | --- | --- |
| D1 | Vendor identity | `389-Directory/2.4.6 …` | distinct `vendorName`/`engineVendor` | Honest advertisement; contract D1 | contract capabilities tests |
| D2 | Admin plane | `cn=config`, `dsconf`, `nsslapd-*` | none; plan applied at start | Native has no 389 tools (contract D2) | bootstrap reconciler tests |
| D3 | Password hash encoding | 389 wire form | same schemes, different blobs | Never compare hashes; bind with plaintext | bind tests |
| D4 | On-disk format | `/data` nsslapd db | bbolt `/data/labldapd.bolt` | Storage is engine-owned | lifecycle tests |
| D5 | Backend name | `userroot` | no backend CN | Suffix, not backend, is the contract | bootstrap tests |
| D6 | Root DSE / entry operational extras | 389 emits `entrydn`, `dsentrydn`, `entryid`, `parentid`, `nsuniqueid` on `+` | honest advertisement; omits 389-specific attrs | Capability inspection is measured, not name-assumed | `TestDifferential389Oracle/search-base-attrs` (strips the 389 set) |
| D7 | Assertion absence path | Pinned 389 does **not** implement RFC 4528: `unavailableCriticalExtension(12)` on critical assertion; OID `1.3.6.1.1.12` not advertised (CAND-25/26) | must advertise and honor | Absence path, not “389 honors assertion.” Control uses `assertionEnabledOn` + `checkRev` when the OID is missing | native assertion atomicity tests; D28 / CAND-26 |
| D8 | Bind with malformed DN | `invalidDNSyntax(34)` | `invalidCredentials(49)` | Fail-closed without revealing DN-shape validation to unauthenticated callers | `TestDifferential389Oracle/bind-malformed-dn` |
| D9 | Anonymous bind while disabled | `inappropriateAuthentication(48)` | `unwillingToPerform(53)` | Both deny; code choice differs (CAND-1 adjudicated 2026-08-15; supersedes the earlier "389 observed 53" note) | `TestDifferential389Oracle/anon-bind-disabled` |
| D10 | LDAPv2 bind attempt | `invalidCredentials(49)` | `protocolError(2)` | Native is strict RFC 4511 §4.2; 389 folds version rejection into credential failure | `TestDifferential389Oracle/bind-version-2` |
| D11 | ModifyDN with out-of-suffix `newSuperior` | `affectsMultipleDSAs(71)` | `unwillingToPerform(53)` | Single-suffix native engine has no DSA concept (CAND-4 adjudicated 2026-08-15) | `TestDifferential389Oracle/modifydn-cross-suffix` |
| D12 | Paged-results cookie tamper | accepts tampered cookie, `success(0)` — no integrity protection | HMAC-SHA256 cookie (offset + base DN + scope + filter) fails closed with `unwillingToPerform(53)` | Native is deliberately stricter (T-140); 389's cookie is an opaque connection-slot index (CAND-5/CAND-18 adjudicated 2026-08-15) | `TestDifferential389Oracle/paged-tampered-cookie` |
| D13 | WhoAmI bound authzId rendering | `dn: cn=directory manager` (space after `dn:`, case-folded) | `dn:cn=Directory Manager` (no space, as-bound case) | Both are valid RFC 4532 authzIds; rendering only (CAND-20 bound case, adjudicated 2026-08-15) | `TestDifferential389Oracle/whoami-bound` |
| D14 | WhoAmI anonymous, anonymous access disabled | `inappropriateAuthentication(48)` — the op itself is refused | ~~`success(0)` with present-empty responseValue~~ **collapsed** (KD-6 / PR-2B): native now also refuses 48 | Both engines refuse the op when anonymous is off. Residual CAND-20 Delta is bound authzId rendering (D13). Committed ledger oracle WhoAmI-anonymous column is still the T-147 recorded success+empty (not rewritten). | `TestDifferential389Oracle/whoami-anonymous`; `TestWhoAmIAnonymousOffRefused` |

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
| CAND-19 | Assertion control scope on non-Modify ops | `unavailableCriticalExtension(12)` on critical non-Modify; `assertionFailed(122)` on mismatch | `delta-ledger.json` verdict `match` |
| D14 / CAND-20 anonymous | WhoAmI with anonymous access off | `inappropriateAuthentication(48)` on both (differential pin). Residual CAND-20 Delta is bound authzId rendering (D13). | KD-6 / PR-2B; `TestWhoAmIAnonymousOffRefused` |
| D21 / CAND-15 | self/all/anyone with anonymous off | pre-bind `anyone` / `all` reads refuse 48 on both | KD-6 / PR-2B; `delta-ledger.json` verdict `match` |
| D24 / CAND-22 | Pre-bind Root DSE with anonymous off | `inappropriateAuthentication(48)` on both | KD-6 / PR-2B; `delta-ledger.json` verdict `match` |

## Deltas adjudicated by T-147's oracle probes

The differential harness adjudicated D8–D14. T-147's parity probes
([`test/parity/probes.go`](https://github.com/hilather/go-lab-ldap-mcp/blob/main/test/parity/probes.go),
recorded in
[`test/parity/delta-ledger.json`](https://github.com/hilather/go-lab-ldap-mcp/blob/main/test/parity/delta-ledger.json))
adjudicated the remaining Wave-1 candidates against the same pinned 389
oracle. Each `delta` verdict below is an accepted engine difference; the
controlling evidence is the named probe plus the ledger's `oracle` /
`native` outcome columns. D-numbers continue the sequence from D14.
Polarity below follows the JSON, not earlier human drafts. These IDs
are also in contract section 3 (2026-08-16).

| Ref | Topic | 389 (observed) | Native (observed) | Verdict |
| --- | --- | --- | --- | --- |
| D15 (CAND-2) | `approxMatch` filter semantics | real approx matching, extra step returns the entry | folds to equality (one step returns nothing) | delta |
| D16 (CAND-6) | ModifyDN rename into own subtree | rejects, `unwillingToPerform(53)`; subtree stays put | **Closed:** same reject; tree intact | match |
| D17 (CAND-8) | Schema MAY / unknown-attribute enforcement on writes | marker-extra and unknown-attr adds both `objectClassViolation(65)`; follow-up reads `noSuchObject(32)` | **Closed:** same 65 / follow-up 32. Marker stays `description` JSON (OD-012). `aci` is MAY on `top`. | match |
| D18 (CAND-9) | Password-policy-violation write code | `constraintViolation(19)` | ~~`unwillingToPerform(53)`~~ **Closed:** `constraintViolation(19)` | match |
| D19 (CAND-10) | Lockout bind failure code | 5th failure → `constraintViolation(19)`; 389 stamps `accountUnlockTime`/`nsUniqueId`/`passwordRetryCount` | 5th failure → `invalidCredentials(49)`; native stamps `pwdAccountLockedTime`/`pwdChangedTime` | delta (C4 is lockout *effect* + bind-test `locked`, not a single marker attr) |
| D20 (CAND-11) | Re-setting the current password | rejected, `constraintViolation(19)` | ~~rejected as in-history, `unwillingToPerform(53)`~~ **Closed:** same reject with 19 | match (both reject; codes agree) |
| D21 (CAND-15) | self/all/anyone bind-rule semantics | anonymous under `anyone` denied `inappropriateAuthentication(48)` when anonymous is off | ~~anonymous read of `ou=probe-anyone` allowed, `success(0)`~~ **collapsed** (KD-6 / PR-2B): native also refuses 48 | match |
| D22 (CAND-17) | groupdn membership scope (nesting) | nested groupdn grant resolves, leaf readable both times | second groupdn read returns empty (no nesting) | delta |
| D23 (CAND-21) | Malformed-DN bind result code | `invalidDNSyntax(34)` | `invalidCredentials(49)` | delta (same divergence as D8; T-147's ledger records it as `CAND-21`) |
| D24 (CAND-22) | Pre-bind Root DSE read with anonymous off | anonymous op refused `inappropriateAuthentication(48)` | ~~pre-bind Root DSE read allowed, `success(0)`~~ **collapsed** (KD-6 / PR-2B): native also refuses 48 | match |
| D25 (CAND-23) | Compare against an absent attribute | `noSuchAttribute(16)` | `compareFalse(5)` | delta |
| D26 (CAND-24) | memberOf auxiliary object class add/retract | **keeps** leftover `nsmemberof` after last-member removal | **Closed:** same leftover `nsmemberof` after retract | match |
| D27 (CAND-25) | `supportedLDAPVersion` advertises v2 | `2, 3` | `3` only | delta |
| D28 (CAND-26) | Critical RFC 4528 assertion on Modify | `unavailableCriticalExtension(12)` on critical assertion; OID not advertised; non-critical fail is ignored and the modify commits (`description=assert-v3`) | advertised and honored: passing critical commits (`description=assert-v5`); fail → `assertionFailed(122)` | delta |
| D29 (CAND-27) | DM password reset vs history policy | DM reset bypasses history, `success(0)` throughout | ~~DM reset of an in-history password rejected, `unwillingToPerform(53)`~~ **Closed:** DM BypassACI skips history, `success(0)` | match |
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
