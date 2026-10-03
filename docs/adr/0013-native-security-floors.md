# ADR 0013: Native security floors for operational attributes and Bind identity

## Status

Proposed — owner directed proposal-only review on 2026-10-03; current parity remains unchanged.

Date: 2026-10-03

Related: ADR-0008, ADR-0009; native-engine parity contract C1/C3/C8 and proposed
D31/D32. This proposal changes the native safety floor, not the public REST,
MCP or configuration contract.

## Evidence

The direct LDAP regression suite against the pinned 389 DS 2.4.6 oracle found:

1. A runtime account with the compiled people-write ACI can modify
   `modifyTimestamp;lang-en`. Native already protects server-owned operational
   attributes, but exact-name checks let options bypass this protection.
2. After a successful Directory Manager bind, a Bind carrying an unknown
   critical control returns `unavailableCriticalExtension(12)` on both engines.
   The pinned 389 instance retains the Directory Manager identity after this
   failure. Native currently does the same because its identity reset occurs
   after control validation.

Evidence: direct LDAP review probes against `LABLDAP_IT_ENGINE=389ds` and
`=native` on 2026-10-03. The oracle accepted `modifyTimestamp;lang-en`
(`success(0)`) and rejected the operational OID `2.5.18.2` with
`unwillingToPerform(53)`; current native accepts the option spelling and rejects
the OID with `constraintViolation(19)`. Both engines retained Directory Manager
after an unknown-critical-control Bind returned 12. These probes are recorded
in the review evidence; proposal-only behavior assertions do not ship in the
regression suite.

The existing AGENTS rule requires the same client-visible results in both
engines; ADR-0008 makes 389 the oracle unless a reviewed Delta is recorded.
An owner decision is therefore required before accepting these differences.

## Proposed decision

1. Native security checks resolve schema OID aliases and attribute options to
   their underlying type. An option cannot turn a server-owned operational
   attribute into a client-modifiable attribute. Proposed D31 records native
   rejection where the pinned 389 build accepts the operational option write.
2. Every native Bind attempt resets the connection identity before validating
   controls or credentials. A failed Bind must leave the anonymous identity.
   Proposed D32 records the pinned 389 critical-control failure behavior.
## Existing implementation context

Matched hardening in the companion implementation PR, separate from proposed decisions 1–2:

3. Previously dispatched native
   operations capture their original subject on
   the connection read loop. A later Bind cannot grant earlier requests a new
   identity or change the authorization used halfway through an operation.
4. Attribute-target ACI protections for options/OIDs retain shared 389/native
   denial tests. They are matched Contract behavior, separate from D31.
5. This does not weaken 389-mode access controls or claim that the underlying
   pinned 389 implementation has been changed. Mode-specific security floors
   must be documented and tested explicitly.

## Consequences

If accepted, native would become stricter on the two observed cases. Existing
native operational attribute protections would apply consistently across
attribute spellings, and failed native Bind attempts would not retain
authenticated privileges. Both engines would remain available, with explicit
tests recording the differences.
No new listener, endpoint, schema field or credential distribution is added.
