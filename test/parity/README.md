# Dual-engine parity tests (T-147)

Contract-tier comparison of the pinned 389 Directory Server (the oracle)
and the native engine (`internal/ldapserver`, run in-process), per
[`docs/design/native-engine-parity-contract.md`](../../docs/design/native-engine-parity-contract.md).

## What lives here

| File | Build | Purpose |
| --- | --- | --- |
| `fixture.go` | always | One scenario compiled once (`internal/config`), the identical LDAP seed sequence for both engines, and outcome canonicalization (DN folding, secret stripping, presence-only operational attrs). |
| `engine.go` | always | The engine abstraction (dial/bind/controls) plus assertion-control, WhoAmI, paged-results, and raw-wire helpers (SASL bind, anonymous/simple LDAPv2 binds go-ldap refuses to send). |
| `native.go` | always | The native engine fixture: an in-process `ldapserver.Server` on a temp bbolt store with the compiled ACI set, plugins, and password policy — the same Options mapping as `cmd/labldapd`. No Docker. |
| `oracle.go` | `integration` | The 389 oracle: a pinned container (image digest from `deploy/docker/dirsrv.digest`) plus the same `dsconf` configuration the production reconcilers apply (backend, dynamic plugins, memberOf+referint plugins with `--autoaddoc nsmemberof`, password policy, bind policy), with the memberOf fix-up task run after seeding. |
| `cases.go` | always | Contract-tier cases (C1–C10 rows): bind/transport gating, search scopes/filters/limits, add/modify/delete/compare/modifyDN, controls, memberOf/referint, runtime ACI matrix, password-policy effects, lockout, tree shape, WhoAmI. |
| `probes.go` | always | The CAND-1…CAND-28 adjudication probes (CAND-21…28 were added during the first dual-engine adjudication run; see the ledger). |
| `compare_test.go` | `integration` | The dual-engine run: Contract mismatches fail the build; CAND outcomes are recorded into the delta ledger. |
| `native_test.go` | always | Hermetic run: all cases/probes against native only, verified against the ledger's native columns; engine-log secret scan. |
| `excluded_test.go` | always | Excluded-tier (E1–E8) inertness on the native surface. |
| `ledger_test.go` | always | Structural validation of the committed ledger. |
| `delta-ledger.json` | — | The adjudicated golden ledger T-150 consumes. |

## Running

```bash
# Hermetic (native only, no Docker):
go test ./test/parity/

# Dual-engine (requires Docker; skips cleanly without it):
go test -tags integration ./test/parity/

# Re-adjudicate and rewrite the ledger after an intentional engine change:
PARITY_UPDATE_LEDGER=1 go test -tags integration ./test/parity/ -run TestDualEngineParity
```

The ledger is a golden file. `go test` (either mode) never rewrites it
without `PARITY_UPDATE_LEDGER=1`; drift in either engine's observed
behavior fails the run.

## Rules encoded here

- Contract cases compare result codes, canonical DN sets, and attribute
  sets with secrets stripped; search order is never compared (contract
  section 5 rule 3). Where the first adjudication run proved a Contract
  step unholdable against the oracle, the step was narrowed to the
  agreed behavior and the divergence moved to a CAND probe:
  - DSE reads happen as an authenticated user (pre-bind DSE access is
    CAND-22); `supportedLDAPVersion` asserts v3-presence (exact set:
    CAND-25); `supportedControl`/`supportedExtension` assert the
    contract-required OIDs only (exact sets: CAND-25); vendor identity
    is presence-only in canon (D1, asserted raw in `compare_test.go`).
  - The subschema is read at the DN advertised in `subschemaSubentry`
    (`cn=subschema` is a 389 alias native does not carry);
    `pwdAccountLockedTime` publication is CAND-28.
  - RFC 4528 assertion semantics are not dual-engine Contract: the
    pinned 389 does not implement the control (CAND-26). Native's
    honor-and-advertise behavior (D7) is locked through the native
    columns of CAND-19/26 in the ledger.
  - Password-policy refusal codes are normalized to "policy-rejected"
    (exact codes: CAND-9); the lockout case normalizes the locked-bind
    code (exact codes and lock-marker attributes: CAND-10, which uses a
    dedicated account so the Contract lockout cannot pollute it).
  - Member-entry object classes are compared only on never-membered
    entries (389 keeps the auto-added `nsmemberof` class after memberOf
    retraction; native drops it — CAND-24).
- `userPassword` and password history never enter an outcome, a log, or
  the ledger; 389-internal operational attributes (`entryid`,
  `parentid`, `entrydn`, `dsentrydn`) are dropped as non-comparable.
- Contract mismatch that is not a ledger-logged Delta ⇒ build failure.
- A CAND probe whose columns differ is a reported Delta, not a failure;
  a CAND probe whose columns changed since adjudication ⇒ build failure
  until the ledger is deliberately regenerated.
- go-ldap refuses client-side to send some wire-legal requests
  (anonymous simple bind, LDAPv2 bind); CAND-1/CAND-21 use raw BER so
  the observed codes are the servers', not the client library's.
