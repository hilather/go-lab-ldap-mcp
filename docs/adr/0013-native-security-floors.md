# ADR 0013: Native security floors for operational attributes and Bind identity

## Status

Proposed

Date: 2026-10-03

Deciders: repository owner

Related tasks: none yet (deliberately). Unlike ADR-0014, which reserves
T-151, this ADR reserves no task id: both decisions change accepted parity
(two new Deltas), so the implementation task is opened in `TASKS.md` only
if the owner accepts them.

Related ADRs: ADR-0008, ADR-0009, and ADR-0014 (merged in #24). Related contract clauses: native-engine parity contract C1/C3/C8, and
the proposed deltas D32/D33. Related fix: PR #25 (control-plane option and
OID handling for protected attributes; adds accepted Delta D31).

## Context

AGENTS requires the same client-visible results from both engines. ADR-0008
makes the pinned 389 build the oracle unless a reviewed Delta is recorded. The
direct LDAP regression suite against the pinned 389 DS 2.4.6 oracle found two
differences that need an owner decision.

### 1. Attribute options on server-owned operational attributes

Evidence comes from direct LDAP review probes against `LABLDAP_IT_ENGINE=389ds`
and `=native` on 2026-10-03.

On LDAP, a runtime account holding the compiled people-write ACI can modify
`modifyTimestamp;lang-en`:

- 389 returns `success(0)`.
- Current native also accepts it. `clientModifiable` and `AttributeType` do
  not strip options (`internal/ldapserver/op_attrs.go:103-111`,
  `schema_registry.go:83-86`), and the schema check does not reject the
  unknown name (`schema_registry.go:305-340`).
- Native stores the value under that exact name (`op_write.go:323-329`). The
  canonical `modifyTimestamp` stays server-owned (`op_attrs.go:94-96`).

Until options are resolved, native's acceptance of this write is D17
behaviour ("Schema MAY / unknown-attribute enforcement on writes"): native
accepts the option spelling as an unknown name. 389 also accepts it, but for a
different reason: it treats `;lang-en` as an option on a known type. So there
is no client-visible split on this case today.

The bare OID `2.5.18.2` is a separate case. Native rejects it with
`constraintViolation(19)` (`op_write.go:153-162`); 389 returns
`unwillingToPerform(53)`. That 19-vs-53 split is the existing unadjudicated
note at `op_write.go:153-156`. D32 does not decide it, and it remains open.

The control plane could reach this case too, and on `main` at `4f05463` it
had an exact-name gap: `ForbiddenEntryAttr`, `ForbiddenUserAttr` and read
redaction compared lowercased full names, so option spellings of protected
names passed REST/MCP writes and came back unredacted on reads, on both
engines (both control planes use the `ds389` runtime). That was a bug
against the existing contract, not a parity question, and it is fixed
separately in PR #25: the control plane now resolves attribute options
and a static table of protected OIDs before the deny checks and read
redaction, rejects every numeric-OID attribute name on operator writes, and
the native engine hashes plaintext values of any variant
`userPassword` spelling (accepted Delta D31, because 389 stores them as
written). This ADR depends on that fix and does not own it. What remains
here is the native LDAP floor: whether native itself rejects option
spellings of server-owned operational attributes on direct LDAP writes.

### 2. Bind identity after a failed critical-control Bind

After a successful Directory Manager bind, a Bind that carries an unknown
critical control returns `unavailableCriticalExtension(12)` on both engines.
Both engines then keep the Directory Manager identity:

- The pinned 389 instance retains it.
- Native retains it because `handleBind` validates controls before
  `authenticate` (`internal/ldapserver/op_bind.go:47-50`). The reset to
  anonymous happens only inside `authenticate` (`op_bind.go:70-71`).

RFC 4513 §4 (and RFC 4511 §4.2.1) say receiving a Bind moves the association to anonymous, and a
failed Bind leaves it anonymous.

Native already has a related exposure on main. `serve()` runs Bind inline with
no outstanding-operation barrier (`conn.go:109-115`), and `handleCompare` reads
`c.subject()` inside the worker (`op_write.go:446`). Every handler started
via `spawnOp` does the same, including Search (`op_search.go:29`), Add,
Modify, Delete, ModifyDN and WhoAmI. Only Bind and StartTLS run inline. So
operations dispatched before a Bind can already see the identity that Bind
sets. D33 does not create
this race. However, under D33 a Bind that fails a critical control would also
change the identity, so more Binds would change the identity that in-flight
workers can observe. That is why the order of steps inside Bind matters.

These probes are recorded in the review evidence. Assertions for proposal-only
behaviour do not ship in the regression suite.

### Existing implementation context

The companion implementation PR (#19) adds matched hardening. It is separate
from D32 and D33:

- Native operations capture their subject on the connection read loop when
  they are dispatched, so a later Bind cannot give earlier requests a new
  identity part-way through.
- Attribute-target ACI protections for options and OIDs (`aci;lang-en` and the
  `aci` OID both return `insufficientAccessRights(50)`) have shared 389/native
  denial tests. That is matched Contract behaviour, separate from D32.
  `clientModifiable` on that branch still does not strip options.
- Nothing here weakens 389-mode access controls or claims that the pinned 389
  implementation changes. Mode-specific security floors must be documented and
  tested explicitly.

## Decision

Proposed:

1. **D32: option stripping for client-modifiability.** Native already
   resolves OIDs to schema types (`Registry.AttributeType`); D32 also strips
   attribute options, including on OID spellings such as
   `2.5.18.2;lang-en`, before the `Operational` check, and rejects through
   the existing `errOperationalAttr` path (`constraintViolation(19)`). An option cannot make a server-owned operational attribute
   client-modifiable. Native rejects the write where the pinned 389 build
   accepts it, and the delta records that split.
   - Acceptance needs a direct LDAP assertion on both engines: native rejects,
     389 records success as the delta.
   - The control plane already rejects option and OID spellings of
     protected names on both engines after PR #25, so REST/MCP results
     stay engine-neutral whatever is decided here. D32 changes only direct
     LDAP results: option spellings of server-owned operational attributes
     return success on 389 today, while OID spellings vary (for example
     `unwillingToPerform(53)` for `2.5.18.2`).
   - Acceptance also needs a control-plane regression on both engines
     (`modifyTimestamp;lang-en` through REST entry update and MCP
     `ldap_update_entry`), extending the PR #25 tests rather than adding
     a second resolver.
   - Rejected alternative: the control plane forwards the write and REST/MCP
     results differ by engine.
2. **D33: native resets; 389 retains; the delta records the split.** Every
   native Bind attempt resets the connection identity to anonymous before it
   validates controls or credentials. A failed Bind leaves the connection
   anonymous. The pinned 389 build keeps the prior identity after a
   critical-control failure, and the delta records that split. It does not
   adopt 389's retention.
   - **Why RFC 4513 §4 wins over RFC 4511 §4.1.11.** §4.1.11 says an
     operation with an unrecognised critical control must not be performed,
     which can be read as supporting 389: resetting the identity is part of
     performing the Bind. This ADR reads RFC 4513 §4 as moving the
     association to anonymous on receipt of the Bind request, before any
     processing, so the reset is not part of the refused operation. That
     reading also fails closed: a refused Bind never leaves elevated
     privileges in place.
   - **Order inside Bind processing:**
     1. ADR-0014's barrier completes or abandons every earlier operation.
     2. Reset to anonymous.
     3. `checkControls`.
     4. `authenticate`.

     Operations dispatched before the Bind keep the subject captured on the
     read loop, and no handler can observe the reset or the new identity.
   - **Implementation precondition.** Do not implement D33 before both of these
     are on main: #19's per-operation subject capture on the read loop, and
     ADR-0014's outstanding-operation barrier.

## Consequences

### Positive

- Native operational-attribute protections apply the same way to every
  attribute spelling.
- A failed native Bind no longer retains authenticated privileges, which
  matches RFC 4513 §4.
- Control-plane rejection keeps REST and MCP results engine-neutral for
  forbidden attributes.

### Negative

- Native becomes stricter than the pinned 389 oracle on two observed cases.
  That adds two accepted Deltas, each with per-engine controlling tests.
- The control-plane tightening this ADR relies on (PR #25) already
  changes the callers of the deny checks, including read redaction
  (`app/directory.go:227`), user create and update
  (`app/users.go:245`, `ds389/runtime.go:297`), entry create and update
  (`ds389/entries.go:423`, `:330`), the seed (`ds389/seed.go:335`), and
  config validation of `users[].attributes` (`internal/config/user.go:54`).
  REST and MCP on the 389 engine reject option spellings of protected names
  that 389 itself accepts, and every numeric-OID attribute name, and scenarios or imports that used them fail validation. That
  compatibility note ships with PR #25; D32 adds only the direct LDAP
  rejection on native.
- D33 cannot ship until #19 and ADR-0014 are implemented.

### Neutral / follow-up

- When implemented, add D32 and D33 rows to `docs/design/parity-delta-log.md`
  (D31 is taken by PR #25) and regenerate the ledger with
  `PARITY_UPDATE_LEDGER=1`. If numbering moves before then, the recording
  rule (next free number) wins over the names used here.
- The control-plane resolver is PR #25's; PR #18 extends it for
  user-write alias spellings. D32's native floor should reuse the same OID
  table rather than add a second one.
- The comment at `internal/ldapserver/op_bind.go:40-42` says every Bind
  first resets to anonymous (RFC 4511 §4.2.1); the code runs
  `checkControls` first. Correct the comment with D33.
- No new listener, endpoint, schema field or credential distribution is added.

## Alternatives considered

| Option | Why not chosen |
| --- | --- |
| Adopt 389 retention after a failed critical-control Bind | Arguably supported by RFC 4511 §4.1.11, but conflicts with RFC 4513 §4 (identity moves to anonymous on receipt) and keeps privileges after a failed Bind; see D33. |
| Leave operational-attribute option spellings under D17 permanently | D17 covers unknown-attribute acceptance. It should not let a server-owned attribute become writable through an option. |
| Reject option spellings only in the control plane (the state after PR #25) | Leaves direct LDAP writes on native open. |
| Reject on native LDAP only and let REST/MCP forward | REST/MCP results would differ by engine. |

## Notes

- On 2026-10-03 the owner asked for a proposal-only review. Current parity is
  unchanged.
- The 19-vs-53 code split for `2.5.18.2` is not decided here.
- Code line references are to `main` at `4f05463`.
