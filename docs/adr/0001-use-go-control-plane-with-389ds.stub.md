# ADR 0001 (stub)

**Status:** title only — **not** an accepted ADR. The no-listener-in-Go intent
for the **control plane** is preserved by [ADR-0008](0008-dual-directory-engines.md).
The first-release rejection of “implement LDAP in Go” is **superseded** by
ADR-0008 for the scoped native daemon (`labldapd`) only.

**Title (from MANIFEST.md):** Decision to use Go around 389 Directory Server
rather than implement LDAP.

**Matching non-negotiable:** `labldap` and `labldap-bootstrap` do not implement
the LDAP wire protocol. `labldapd` may (ADR-0008, ADR-0009).

Do not invent rejected options, consequences, or full ADR body text. Do not
cite this stub as an accepted decision.
