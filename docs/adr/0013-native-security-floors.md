# ADR 0013: Native security floors for operational attributes and Bind identity

## Status

Proposed

Date: 2026-10-03

Deciders: repository owner

Related tasks: none yet. An implementation task is opened in `TASKS.md` when
this ADR is accepted.

Related ADRs: ADR-0008, ADR-0009, and ADR-0014 (proposed in PR #24, not yet
on main). Related contract clauses: native-engine parity contract C1/C3/C8, and
the proposed deltas D31/D32.

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

Until options are resolved, native's acceptance of this write falls under D17,
"Schema MAY / unknown-attribute enforcement on writes". In that ledger row 389
rejects unknown attributes and native accepts them.

The bare OID `2.5.18.2` is a separate case. Native rejects it with
`constraintViolation(19)` (`op_write.go:153-162`); 389 returns
`unwillingToPerform(53)`. That 19-vs-53 split is the existing unadjudicated
note at `op_write.go:153-156`. D31 does not decide it, and it remains open.

The control plane can reach this case too. REST entry update and MCP
`ldap_update_entry` forward the attribute name
(`internal/directory/ds389/entries.go:325-331`). `ForbiddenEntryAttr`
(`internal/directory/classes.go:103-113`) and `ForbiddenUserAttr` both
compare against `config.CanonicalAttr`, which only lowercases and trims
(`internal/config/attr.go:26-32`). That means option spellings of every name
on those deny lists get through, not just `modifyTimestamp`: `userPassword;…`,
`memberOf;…`, `nsAccountLock;…`, `aci;…`, `entryUUID;…` and the other
`operationalDeny` names. The `nsslapd-` prefix check still catches option
suffixes. If native alone started rejecting these writes, REST and MCP would
return different results depending on the engine.

Read redaction has the same exact-name gap. REST and MCP read output is
filtered through `redactAttrs` / `secretOrDeniedAttr`
(`internal/app/directory.go:184`, `:225-228`), which match names exactly. An
option spelling such as `userPassword;lang-en` or `nsslapd-rootpw;x` is
therefore not redacted. On the 389 engine, REST can already write
`userPassword;lang-en` today and read it back unredacted. That gap exists on
main now and is tracked separately from D31.

### 2. Bind identity after a failed critical-control Bind

After a successful Directory Manager bind, a Bind that carries an unknown
critical control returns `unavailableCriticalExtension(12)` on both engines.
Both engines then keep the Directory Manager identity:

- The pinned 389 instance retains it.
- Native retains it because `handleBind` validates controls before
  `authenticate` (`internal/ldapserver/op_bind.go:47-50`). The reset to
  anonymous happens only inside `authenticate` (`op_bind.go:70-71`).

RFC 4513 §4 says receiving a Bind moves the association to anonymous, and a
failed Bind leaves it anonymous.

Native already has a related exposure on main. `serve()` runs Bind inline with
no outstanding-operation barrier (`conn.go:109-115`), and `handleCompare` reads
`c.subject()` inside the worker (`op_write.go:446`). So operations dispatched
before a Bind can already see the identity that Bind sets. D32 does not create
this race. However, under D32 a Bind that fails a critical control would also
change the identity, so more Binds would change the identity that in-flight
workers can observe. That is why the order of steps inside Bind matters.

These probes are recorded in the review evidence. Assertions for proposal-only
behaviour do not ship in the regression suite.

### Existing implementation context

The companion implementation PR (#19) adds matched hardening. It is separate
from D31 and D32:

- Native operations capture their subject on the connection read loop when
  they are dispatched, so a later Bind cannot give earlier requests a new
  identity part-way through.
- Attribute-target ACI protections for options and OIDs (`aci;lang-en` and the
  `aci` OID both return `insufficientAccessRights(50)`) have shared 389/native
  denial tests. That is matched Contract behaviour, separate from D31.
  `clientModifiable` on that branch still does not strip options.
- Nothing here weakens 389-mode access controls or claims that the pinned 389
  implementation changes. Mode-specific security floors must be documented and
  tested explicitly.

## Decision

Proposed:

1. **D31: option and OID resolution for client-modifiability.** Native
   security checks resolve schema OID aliases and attribute options to the
   underlying type. An option cannot make a server-owned operational attribute
   client-modifiable. Native rejects the write where the pinned 389 build
   accepts it, and the delta records that split.
   - Acceptance needs a direct LDAP assertion on both engines: native rejects,
     389 records success as the delta.
   - Acceptance also needs a control-plane assertion on both engines, using
     REST entry update and MCP `ldap_update_entry` with
     `modifyTimestamp;lang-en` and at least one credential-class spelling
     (`userPassword;lang-en`).
   - **Proposed REST/MCP behaviour change.** Entry and user updates reject
     option and OID spellings of every `ForbiddenEntryAttr` and
     `ForbiddenUserAttr` name. They return the existing `changes.name` /
     `forbidden_attribute` error on both engines. This adds no new operation,
     OpenAPI shape or console workflow. On the 389 engine these writes return
     success today.
   - The control plane uses one option-stripping resolver for both the write
     deny check and read redaction. OID spellings are resolved through a
     static table of deny-list OIDs in `internal/config`, because the control
     plane has no schema registry. That table is tested against the subschema
     of both engines so the two lists cannot drift apart.
   - Rejected alternative: the control plane forwards the write and REST/MCP
     results differ by engine.
2. **D32: native resets; 389 retains; the delta records the split.** Every
   native Bind attempt resets the connection identity to anonymous before it
   validates controls or credentials. A failed Bind leaves the connection
   anonymous. The pinned 389 build keeps the prior identity after a
   critical-control failure, and the delta records that split. It does not
   adopt 389's retention.
   - **Order inside Bind processing:**
     1. ADR-0014's barrier completes or abandons every earlier operation.
     2. Reset to anonymous.
     3. `checkControls`.
     4. `authenticate`.

     Operations dispatched before the Bind keep the subject captured on the
     read loop, and no handler can observe the reset or the new identity.
   - **Implementation precondition.** Do not implement D32 before both of these
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
- REST and MCP on the 389 engine start rejecting option spellings that 389
  itself accepts.
- Config validation of `users[].attributes` (`internal/config/user.go:54`)
  uses the same deny check, so it becomes stricter. That is a security
  tightening allowed in a minor release, and it needs a compatibility note.
- D32 cannot ship until #19 and ADR-0014 are implemented.

### Neutral / follow-up

- When implemented, add D31 and D32 rows to `docs/design/parity-delta-log.md`
  (D-numbers on main end at D30) and regenerate the ledger with
  `PARITY_UPDATE_LEDGER=1`.
- The control-plane resolution overlaps with the option and alias handling
  under review for the user-write paths (PR #18). Implement them together so
  there is one write rule.
- No new listener, endpoint, schema field or credential distribution is added.

## Alternatives considered

| Option | Why not chosen |
| --- | --- |
| Adopt 389 retention after a failed critical-control Bind | Conflicts with RFC 4513 §4 and keeps privileges after a failed Bind. |
| Leave operational-attribute option spellings under D17 permanently | D17 covers unknown-attribute acceptance. It should not let a server-owned attribute become writable through an option. |
| Reject option spellings only in the control plane | Leaves direct LDAP writes on native open. |
| Reject on native LDAP only and let REST/MCP forward | REST/MCP results would differ by engine. |

## Notes

- On 2026-10-03 the owner asked for a proposal-only review. Current parity is
  unchanged.
- The 19-vs-53 code split for `2.5.18.2` is not decided here.
- Code line references are to `main` at `4f05463`.
