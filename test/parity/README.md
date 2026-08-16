# Dual-engine parity tests (T-147)

Contract-tier comparison of the pinned 389 Directory Server (the oracle)
and the native engine (`internal/ldapserver`, run in-process), per
[`docs/design/native-engine-parity-contract.md`](https://github.com/hilather/go-lab-ldap-mcp/blob/main/docs/design/native-engine-parity-contract.md).

Observation source of truth is the structured `oracle` / `native`
outcomes in this directory's
[`delta-ledger.json`](https://github.com/hilather/go-lab-ldap-mcp/blob/main/test/parity/delta-ledger.json).
Probe *code* and step comments in
[`probes.go`](https://github.com/hilather/go-lab-ldap-mcp/blob/main/test/parity/probes.go)
may narrate those steps only when they do not contradict the JSON; if a
comment disagrees, the JSON wins. The human adjudication record is
[`docs/design/parity-delta-log.md`](https://github.com/hilather/go-lab-ldap-mcp/blob/main/docs/design/parity-delta-log.md).
If that log disagrees with the JSON, the JSON wins.

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
| `delta-ledger.json` | — | Machine observation SoT. Adjudicated golden ledger T-150 consumes. Delta verdicts CAND-2/6/8/10/15/17/21–26/28 are D15–D30 in the contract. CAND-9/11/27 match after the native password-policy write-path fix. |

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
  - RFC 4528 assertion semantics are not dual-engine Contract (C9): the
    pinned 389 does not implement the control — `unavailableCriticalExtension(12)`
    on critical Modify, OID omitted (CAND-26 / D28). Native advertises
    and honors it (D7). The control plane uses `assertionEnabledOn` +
    `checkRev`. Native honor-and-advertise is locked through the native
    columns of CAND-19/26 in the ledger.
  - Password-policy refusal codes are normalized to "policy-rejected"
    (exact codes: CAND-9 / D18). Contract C4 lockout is the *effect* plus
    bind-test `locked` (not a single marker attribute). The lockout case
    normalizes the locked-bind code; exact codes and lock-marker
    attributes are CAND-10 / D19 (dedicated account so the Contract
    lockout cannot pollute it). Native may publish extra lock attrs.
  - Member-entry object classes are compared only on never-membered
    entries (D26 / CAND-24: 389 **keeps** leftover `nsmemberof` after
    last-member removal; native **retracts** it today).
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
