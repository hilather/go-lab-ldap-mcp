# ADR 0014: Outstanding operations during LDAP reauthentication

## Status

Proposed

Date: 2026-10-03

Deciders: repository owner

Related tasks: T-151 (decide and implement Bind handling of outstanding operations)

Related ADRs: ADR-0008, ADR-0009. ADR-0013 is a separate Proposed ADR in PR #23
and is not on main.

## Context

This scheduling gap was found during final oracle validation on 2026-10-03.
This proposal does not authorize any behaviour change or accepted parity Delta.
The gap is separate from the two proposals in ADR-0013 (operational attributes
and the failed critical Bind). The earlier owner decision covered only
ADR-0013's two findings. The owner has not decided on this third finding.

### Evidence

The probe used a raw TLS BER client:

1. It bound successfully as a low-privilege Alice account.
2. It sent Compare request ID 1 for an existing, known-true `uid` value.
3. It sent a Directory Manager Bind request ID 2 immediately after.
4. It waited for the BindResponse, then sent its next Compare (ID 3).

Responses were matched by message ID, not by arrival order. No credentials
were recorded.

Earlier isolated runs saw `[50, 0, 6]` for IDs 1/2/3 on both native and
pinned 389 DS 2.4.6, across twenty connections per engine. Final concurrent
oracle validation got `[48, 0, 6]` from 389 at iteration 1, even though the
initial Alice Bind succeeded.

The 389 result 48 fits its anonymous-access gate applying while the
connection's authentication is changing. That cause is an inference, not an
instrumented server trace. Both observed denial codes prevented a privileged
comparison. However, 48 and 50 are different client-visible outcomes and are
not treated as equivalent. Until a delayed-operation probe runs, the 389
oracle for this sequence is unstable. The earlier isolated passing runs did not
establish stable exact parity for the overlapping sequence. No accepted Delta
covers this outstanding-operation behaviour.

The evidence logs come from the final review. `final-bind-parity.log` records
the failing 389 tuple. The bounded direct-probe logs record native response
ordering and the isolated engine results. These are review artifacts, not
committed credentials or generated fixtures.

### Native evidence baseline (current PR #19 coverage, not main)

The native results come from PR #19's build (`review/fix-native-safety`).
That build captures each operation's subject on the read loop when the
operation is dispatched. Commit `819d046c` introduced this. The capture is a
context value of `c.subject()` under `operationSubjectKey` in
`internal/ldapserver/conn.go`. The build still calls `handleBind` inline with
no barrier: as of PR head `90b3ef78c5117199d7343755d35e9b6527fd29b4`,
`conn.go:113` still does this.

On that build, native returned `[50, 0, 6]` in every observed run. It often
sent BindResponse ID 2 before CompareResponse ID 1, which fits the missing
barrier. Ordering was not asserted.

PR #19 tests a stable sequence with exact codes `[50, 0, 6]`: Alice Bind,
denied Compare, Directory Manager Bind, then a successful Compare. That
establishes authorization parity for the sequential case.

A separate supported fixture enables anonymous access but grants Compare
permission to neither Alice nor anonymous callers. In that fixture, explicit
control requests must both return 50 before the overlapping sequence is tested
with exact `[50, 0, 6]` results.

What that fixture shows: the overlapping Compare did not run as Directory
Manager. What it does not show:

- which denied identity the Compare ran as;
- that the Compare finished before the Bind was processed;
- exact parity for overlapping operations under the default fixture, where
  anonymous access is disabled.

### Current behaviour on main

Code references are pinned to `4c0b66a`.

- `serve()` calls `handleBind` inline. It does not check in-flight operations
  and does not abandon them (`internal/ldapserver/conn.go:109-115`).
- Because Bind runs inline, the next PDU is not read until Bind returns. The
  gap is work already handed to workers (`conn.go:252-259`).
- Compare reads `c.subject()` inside the worker
  (`internal/ldapserver/op_write.go:446`).

So on main, if Bind reaches `setSubject` (`internal/ldapserver/op_bind.go:100`)
first, an earlier Compare can run as Directory Manager and return 6. Capturing
the identity alone does not provide the completion or abandon barrier the RFC
requires.

### Protocol and prior art

[RFC 4511 §4.2.1](https://www.rfc-editor.org/rfc/rfc4511.html#section-4.2.1):

- Before processing a Bind, the server must complete or abandon outstanding
  operations. Either is legal.
- Clients must wait for the BindResponse before sending further PDUs. The
  probe followed that rule.
- The server should not process requests that arrive while a Bind is in
  progress.

[RFC 4511 §4.11](https://www.rfc-editor.org/rfc/rfc4511.html#section-4.11):
abandoned operations get no response.

OpenLDAP slapd abandons outstanding operations as soon as it receives a Bind.
It marks the connection `SLAP_C_BINDING`, so later non-Bind operations are
deferred. See `servers/slapd/connection.c` at tag `OPENLDAP_REL_ENG_2_6_10`
(line 1600), comment: "immediately abandon all existing operations upon BIND"
([source](https://git.openldap.org/openldap/openldap/-/blob/OPENLDAP_REL_ENG_2_6_10/servers/slapd/connection.c)).

## Decision

Proposed. Choose and document how outstanding operations are handled before
changing native runtime behaviour.

1. **Drain** prior operations before authentication.
   - Put a connection admission barrier on the read loop.
   - Wait for completion without holding locks the handlers need, then
     process the Bind.
   - Specify cancellation, shutdown and deadline behaviour, so a long-running
     operation cannot block reauthentication indefinitely.
2. **Abandon** prior operations before authentication (OpenLDAP's choice).
   - Specify which updates can finish transactionally.
   - Specify whether responses already in flight remain observable.
   - Specify how completion or abandonment is confirmed before the Bind is
     processed.
   - Do not let a handler acquire the new subject.

Before selecting exact client-visible assertions, observe pinned 389 under two
cases: a controlled delayed operation and concurrent load. If the intended
native guarantee differs from the oracle, AGENTS requires an accepted ADR and a
named parity Delta first. Do not silently normalize 48 and 50, and do not retry
until a favourable outcome appears.

**Acceptance requirement.** The acceptance test for the chosen option must
assert ordering, not only result codes. It must show that the Bind is processed
only after earlier operations completed or were abandoned.

- **Drain:** CompareResponse ID 1 arrives before BindResponse ID 2, and its
  result reflects the identity from before the Bind.
- **Abandon:** no CompareResponse ID 1 arrives after BindResponse ID 2. A
  deterministic native scheduling hook confirms the worker exited before
  `setSubject`. A CompareResponse sent before the BindResponse is allowed,
  provided its result reflects the identity from before the Bind.
  This criterion assumes abandoned operations get no response, by analogy to
  RFC 4511 §4.11 and OpenLDAP's behaviour. RFC 4511 does not define
  responses for operations abandoned by a Bind.
- **Both:** native ordering is checked with deterministic scheduling hooks.
  Once the delayed-operation probe has established the oracle's behaviour,
  the parametrized integration test asserts the same ordering on both engines.
  Where native intentionally differs, it uses a named accepted Delta.

## Consequences

### Positive

- The native Bind path gets an explicit barrier for prior operations, which
  complements the subject capture proposed in PR #19.
- Ordering becomes a tested property, not something inferred from result
  codes.
- The parity question for overlapping operations is recorded explicitly
  instead of being normalized.

### Negative

- Drain can delay reauthentication behind slow operations. That needs
  deadlines.
- Abandon throws away in-flight work. That needs rules for transactional
  updates.
- Exact parity assertions wait on a 389 probe whose behaviour is currently
  unstable.

### Neutral / follow-up

- REST and MCP have no equivalent. `ldapclient.Pool.Do` gives each call one
  exclusive pooled connection
  (`internal/directory/ldapclient/pool.go:111`), so a Bind is never pipelined
  behind an outstanding operation.
- T-151 tracks the decision and its implementation.

## Alternatives considered

| Option | Why not chosen |
| --- | --- |
| Drain prior operations before Bind | Open. The owner selects between drain and abandon after the 389 probe. |
| Abandon prior operations before Bind (OpenLDAP) | Open. The owner selects between drain and abandon after the 389 probe. |
| Keep subject capture only (current PR #19 coverage) | Not proposed. It gives no RFC 4511 §4.2.1 completion or abandon guarantee, and the ordering stays unobservable. |

## Notes

- This proposal changes no production behaviour and no accepted Delta.
- The evidence logs are review artifacts and are not committed.
