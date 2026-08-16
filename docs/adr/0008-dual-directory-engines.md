# ADR 0008: Dual directory engines with LabLDAP-surface parity

## Status

Accepted

Date: 2026-08-15

Deciders: repository owner

Related tasks: T-121 through T-150

Related ADRs: ADR-0009 (native topology and storage); supersedes the *intent* of stub ADR-0001 (Go must not implement LDAP) and amends stub ADR-0002 (engine identity is no longer 389-only; the source-of-truth principle is preserved)

## Context

v0.1.0 ships LabLDAP as a control plane around a pinned 389 Directory Server container. That choice is recorded in README safety model §1, `AGENTS.md` (“Do not implement an LDAP listener or BER protocol engine in Go”), `docs/13-open-decisions.md` §4 (“initial engine profile is 389 DS only”), and design-doc alternative **A1** (“Implement LDAP in Go”) which was rejected for the first release.

The product now has a second goal: a Go-native LDAP server that exposes the same LabLDAP-visible directory behavior, selectable beside 389 DS, so the two engines can be differentially tested. `docs/13-open-decisions.md` §5 requires an ADR before adding a second engine. This document is that decision. It reverses A1 for a **scoped** native engine; it does not reverse the reasons A1 was rejected (do not put protocol in the control plane; do not keep users in a Go map; do not pretend an in-memory fake is LDAP).

Literal 389 feature parity (replication, changelog, the unused plugin catalog, SASL) is out of scope. The contract is [LabLDAP-surface parity](../design/native-engine-parity-contract.md).

## Decision

1. LabLDAP supports **two directory engines**, selected by configuration:
   - `389ds` — the existing pinned 389 Directory Server container. **Default.** Unchanged compose topology.
   - `native` — a Go LDAP server in this repository (`cmd/labldapd` + `internal/ldapserver`), specified by ADR-0009.
2. **389 DS remains the behavioral oracle.** When the engines disagree on a Contract-tier behavior, the native engine is wrong until the [parity contract](../design/native-engine-parity-contract.md) records an explicit, reviewed Delta.
3. **The control plane does not become an LDAP server.** `labldap` and `labldap-bootstrap` stay LDAP *clients*. They must not import `internal/ldapserver` in production code. Native mode talks to `labldapd` over LDAP / LDAPS / StartTLS, the same way 389 mode talks to 389 DS.
4. **Directory data still does not live in the control process.** Users, groups, memberships, password hashes, ACIs, and account state live in the selected engine. An application-only in-memory map remains forbidden.
5. **Privilege separation is unchanged.** Directory Manager is bootstrap-only. The long-running control service never receives the DM secret and never mounts the Docker socket. Soft reset stays suffix-scoped. Hard reset stays an operator compose/volume action.
6. **Parity scope is LabLDAP-surface**, not “all of 389.” Contract / Delta / Excluded tiers in the parity contract are the source of truth. Expanding the Contract tier is a new ADR or a dated amendment of that contract.
7. **Existing public contracts stay stable.** REST, MCP, the UI, and `v1alpha1` remain valid. Engine selection is a backward-compatible optional field defaulting to `389ds` (see T-123). No new REST version.
8. **Native mode is lab-scoped.** It is a laboratory directory, like 389 mode. It is not a production identity system. Docs must not present it as a 389 replacement outside this product.

Rejected options are listed below. Silence would otherwise re-open A1 as “embed LDAP in `labldap`” or “in-memory SoT.”

## Consequences

### Positive

- Operators can run a lab without the 389 container once native mode meets the contract.
- Dual-mode CI treats 389 as oracle and catches native drift as it is introduced.
- The existing `internal/directory` interfaces, `ldapclient` pool, runtime adapter, REST, MCP, and UI are reused; the new work concentrates in the server and native bootstrap reconcilers.
- The “do not implement LDAP in the control plane” safety property is preserved.

### Negative

- The repository now owns a pre-auth network parser (BER, filters, DNs). That attack surface was deliberately avoided at v0.1.0. Fuzzing, size/time limits, and loopback-default listeners are mandatory (T-124, T-125, T-149).
- Every future Contract-tier directory feature must land on both engines, with a parity case at definition of done.
- Calendar cost is 29–44 engineer-weeks (see the M9 plan). Dual-engine maintenance is permanent.
- Capability reports will differ in vendor strings; callers must not assume `engineVendor` is always 389.

### Neutral / follow-up

- ADR-0009 records daemon topology, storage, codec, and package layout.
- `AGENTS.md`, README, `docs/01-system-architecture.md`, and `docs/13-open-decisions.md` are amended in the same change as this ADR.
- Stub ADR-0001 is marked superseded-in-intent by this ADR. Stub ADR-0002 is marked amended: SoT remains “the engine,” engine identity is dual.
- Milestone M9 (`TASKS.md` T-121–T-150) implements the decision. Native is ready as opt-in `engine: native` after M9 exit (T-150). The omitted-field default remains `389ds`.
- `test/enginesuite` stays a 389 observed-behavior inventory. Cross-engine comparison is `test/parity` (T-147).

## Alternatives considered

| Option | Why not chosen |
| --- | --- |
| Keep 389-only (status quo / original A1 rejection) | Rejects the dual-mode product goal. 389 remains the default and the oracle; that is the scoped reversal, not a wholesale replacement. |
| Embed the LDAP listener in `labldap` | Collapses privilege separation, mixes management TLS with directory TLS, and makes “LDAP bind is against the engine” false. Forbidden by decision 3. |
| In-memory map as native SoT | Re-opens rejected design A3. External `ldapsearch` would drift from the control plane. Forbidden by decision 4. |
| Literal 389 feature parity | Multi-year C-surface (replication, changelog, unused plugins, SASL). LabLDAP never exposes it. Tracked as Excluded in the parity contract. |
| OpenLDAP or another third-party engine as engine B | Does not produce a Go-native server in this repo and does not retire the 389 image dependency on our terms. Out of scope; `DirectoryRepository` remains an extension point for a later ADR. |

## Notes

- Accepted ADRs outrank other repository documents. This ADR occupies the AGENTS rank-1 slot for engine choice.
- Security defaults may become stricter in a minor release; insecure behavior must never become the silent default. Native mode inherits 389-mode defaults: anonymous bind off, cleartext simple bind off unless explicit insecure lab mode.
- Do not cite stub ADR-0001 as an accepted decision. This file is the accepted decision.
