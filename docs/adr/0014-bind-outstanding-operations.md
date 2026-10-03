# ADR 0014: Outstanding operations during LDAP reauthentication

## Status

Proposed — discovered during final oracle validation on 2026-10-03. No behavior change or accepted parity Delta is authorized by this proposal.

This is a newly discovered scheduling gap, separate from the two operational-attribute and failed-critical-Bind proposals in ADR-0013. The prior owner decision addressed only ADR-0013's two findings; no owner decision has been made for this third finding.

## Evidence

A raw TLS BER client first successfully bound as a low-privilege Alice account, then sent Compare request ID 1 for an existing, known-true `uid` value immediately followed by a Directory Manager Bind request ID 2. The client waited for BindResponse before sending its next Compare (ID 3). Responses were correlated by ID, not arrival order; no credentials were recorded.

Earlier isolated runs observed `[50, 0, 6]` for IDs 1/2/3 on both native and pinned 389 DS 2.4.6, across twenty connections per engine. Final concurrent oracle validation produced `[48, 0, 6]` from 389 at iteration 1 despite the initial Alice Bind succeeding. Native consistently returned `[50, 0, 6]` in the observed runs, and often sent BindResponse ID 2 before CompareResponse ID 1.

The 389 result 48 is consistent with its anonymous-access gate applying while connection authentication changes; this causal explanation is an inference, not an instrumented server trace. Both observed denial codes prevented privileged comparison. The earlier isolated passing runs did not establish stable exact parity for the overlapping sequence. No accepted Delta currently classifies this outstanding-operation behavior.

Primary protocol basis: [RFC 4511 §4.2.1](https://www.rfc-editor.org/rfc/rfc4511.html#section-4.2.1) requires outstanding operations to complete or be abandoned before processing Bind. Clients must await BindResponse before sending further LDAP PDUs; the probe complied with that client requirement. Source inspection confirms the native read loop calls `handleBind` without completing or abandoning in-flight operations; the observed response order is consistent with that missing barrier. Identity capture alone does not implement the required completion/abandon barrier.

Evidence logs from final review: `final-bind-parity.log` records the failing 389 tuple; the bounded direct-probe logs record native response ordering and isolated engine results. These are review artifacts, not committed credentials or generated fixtures.

## Proposed decision

Choose and document outstanding-operation handling before changing native runtime behavior:

1. Drain prior operations before authentication. Establish a connection admission barrier on the read loop, await completion without holding locks needed by handlers, then process Bind. Specify cancellation, shutdown and deadline behavior so a long-running operation cannot indefinitely prevent reauthentication.
2. Alternatively, cancel/abandon prior operations before authentication. Specify which updates can finish transactionally, whether responses already in flight remain observable, and how to confirm completion/abandonment before Bind processing. Avoid allowing a handler to acquire the new subject.

Observe pinned 389 under both controlled delayed-operation and concurrent-load cases before selecting exact client-visible assertions. If the intended native guarantee differs from the oracle, obtain an accepted ADR and named parity Delta first, as AGENTS requires. Do not normalize 48/50 silently or retry until a favorable outcome appears.

## Consequences

If accepted, the native Bind path would enforce an explicit prior-operation barrier, retaining the independently implemented subject-capture defense. Tests would combine deterministic native scheduling checks with parametrized integration and real-389 parity cases for the selected contract.

The implementation PR currently tests stable sequential Alice Bind → denied Compare → Directory Manager Bind → successful Compare with exact codes `[50, 0, 6]`. That establishes sequential authorization parity. A separate supported fixture enables anonymous access but grants neither Alice nor anonymous callers Compare permission: explicit control requests must both return 50 before the overlapping sequence is tested with exact `[50, 0, 6]` results. This isolates privilege preservation from the anonymous-access gate without normalizing result codes. It does not claim exact parity for overlapping operations under the default anonymous-disabled fixture or RFC completion ordering. No production behavior or accepted Delta changes in this proposal.
