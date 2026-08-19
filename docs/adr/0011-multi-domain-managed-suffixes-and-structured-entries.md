# ADR 0011: Multi-domain managed suffixes and structured entry API

## Status

Accepted

Date: 2026-08-19

Deciders: repository owner

Related tasks: GitHub issue #5

Related ADRs: ADR-0008 (dual engines); ADR-0009 (native topology); ADR-0006 stub (shared application services)

## Context

`spec.directory.suffix` is a single managed naming context. Users and groups
are created only as `uid=<id>,<peopleRDN>,<suffix>` and
`cn=<id>,<groupsRDN>,<suffix>`. Operators cannot build enterprise-style
multi-domain OU trees or place bind users at exact DNs such as:

`CN=svc_bind_region1,OU=ServiceUsers,OU=Shared,OU=Network,OU=Region1,DC=region1,DC=example,DC=net`

Issue #5 asks for multiple configured suffixes, a structured (not raw)
entry API, explicit user/group DNs, tree browse, and the same workflows on
REST, MCP, and the embedded UI.

Constraints that this ADR must preserve:

- No raw arbitrary LDAP modification API (`AGENTS.md`).
- Runtime must not write outside configured managed suffix(es).
- Directory Manager stays bootstrap-only.
- REST and MCP call the same application services; new operator actions
  must be usable from the UI.
- Dual-engine Contract behavior needs a 389 oracle path and a native path.
- Same `apiVersion: labldap.dev/v1alpha1` (backward-compatible addition).

389 Directory Server creates one backend per suffix
(`dsconf backend create --suffix … --be-name … --create-suffix`). Nested
suffixes (a naming context inside another) are not a supported lab pattern.
The MemberOf plugin is configured with a primary `--scope`; extra scopes
are applied as additional `memberOfEntryScope` values when the engine
accepts them. Cross-suffix membership is best-effort on 389: groups and
members in the same managed suffix are the supported memberOf path.

389 has no AD `container` structural class. Native schema matches the
LabLDAP-surface set (domain, organizationalUnit, inetOrgPerson,
groupOfNames) and also lacks `container`.

## Decision

1. **Keep `spec.directory.suffix` as the primary managed suffix.** People,
   groups, the runtime account, and the baseline marker stay under it.

2. **Add optional `spec.directory.additionalSuffixes: []string`.** Each
   value is a distinct, valid DN. Additional suffixes must not equal the
   primary (case-insensitive DN equality), must not equal each other, and
   must not be nested inside the primary or each other. Sibling / unrelated
   trees only (for example `dc=region1,dc=example,dc=net` beside
   `dc=example,dc=test`). Empty or omitted keeps today's single-suffix lab.

3. **Compiled managed suffixes = primary + additional (stable sort).**
   Search bases, write targets, export, inventory extras, ACI targets, and
   engine write gates use this set. Unlisted DNs are rejected as a write or
   search base.

4. **"Multi-domain" means multiple configured suffixes in one lab
   instance.** It is not a separate AD forest, trust, or cross-domain
   GC. Docs must say so.

5. **Bootstrap creates each extra suffix as its own naming context:**
   - 389: an additional backend (`labldapN` in compiled order) with
     `--create-suffix`.
   - Native: `labldapd` advertises every suffix on Root DSE
     `namingContexts`, accepts writes under any of them, and publishes
     `labldapEngineAdditionalSuffixes` on the `cn=config` stub for
     read-back. Tree reconcile creates each extra suffix root as
     `top` + `domain` (dc= RDN).

6. **No automatic people/groups containers under additional suffixes.**
   Operators build OU trees through the structured entry API (or YAML
   later). Soft reset still reseeds primary people/groups; extra suffix
   roots are preserved and operator-created extras under them are
   inventory extras.

7. **Runtime ACIs on the primary suffix stay people/groups-scoped**
   (T-036). Each additional suffix gets suffix-read, suffix-write
   (`targetattr!="aci"`), and password-write ACIs for the runtime
   account. Structured writes under the primary suffix remain limited to
   the people and groups containers by engine ACI. Use
   `additionalSuffixes` for extra OU trees.

8. **Structured entry API (allowlisted classes only).** No free-form BER
   mods, no pass-through modify, no raw ACI dump except the existing
   `allowRawACI` ACL path.

   | Requested class | Stored class |
   | --- | --- |
   | `domain`, `dcObject` | `top` + `domain` (dc= RDN) |
   | `organizationalUnit` | `top` + `organizationalUnit` |
   | `container` | **alias** of `organizationalUnit` (documented; both engines) |
   | `person`, `inetOrgPerson` | existing user class chain |
   | `groupOfNames` | existing group class; OD-018 empty-group rule still applies |

   Parents must already exist. Missing parents return a clear
   `parent_missing` error (no auto-create).

   Operations (MCP names; REST siblings in the same change):

   - `ldap_create_entry` / `POST /api/v1/entries`
   - `ldap_update_entry` / `PATCH /api/v1/entries?dn=`
   - `ldap_delete_entry` / `DELETE /api/v1/entries?dn=` (revision +
     confirm; refuse non-empty containers unless `recursive` + confirm)
   - `ldap_move_entry` / `POST /api/v1/entries/move` (new DN stays under
     a managed suffix; referint/memberof update `member` / `memberOf`)
   - `ldap_list_tree` / `POST /api/v1/tree`
   - `GET /api/v1/suffixes` lists compiled managed suffixes

9. **Search `base` may be any managed suffix or a descendant.** Empty
   base still defaults to the primary suffix. Over-broad match-all
   subtree dumps are rejected at every managed suffix root, not only the
   primary.

10. **Existing user and group services accept optional `dn` or
    `parentDN`.** Placement must be under a managed suffix. Default
    placement is unchanged (`ou=people` / `ou=groups` on the primary).
    Get-by-id searches `uid=` / `cn=` under every managed suffix so
    service users at issue-#5 DNs remain first-class. List stays
    one-level under the primary people/groups containers. Membership
    resolution accepts member DNs under any managed suffix.

11. **`container` is an alias, not an AD class.** Tests assert that a
    create with `objectClasses: ["container"]` yields
    `organizationalUnit` on both engines.

12. **No new `apiVersion`.** `CompilerContract` stays
    `labldap.config.v1alpha1.3`. Additional suffixes enter the directory
    revision hash only when the list is non-empty, so omitted-field
    labs keep today's hash.

Rejected options: a raw LDAP modify/pass-through API; treating nested
`dc=regionN,dc=example,dc=net` as children of a single
`dc=example,dc=net` backend when the operator listed them as additional
suffixes; embedding an LDAP listener in the control plane.

## Consequences

### Positive

- Operators can model several regional naming contexts in one lab.
- Service-account DNs can match customer trees without a second user model.
- Write and search gates stay suffix-scoped on a compiled allow-list.
- REST, MCP, and the UI share one application service.

### Negative

- 389 MemberOf / referint extra scopes are engine-dependent. Cross-suffix
  membership may not refresh `memberOf` on 389; same-suffix membership is
  the supported path and is what dual-engine tests assert.
- Primary-suffix ACI stays people/groups-scoped. Extra OU trees belong in
  `additionalSuffixes` (or under people/groups). Expanding primary
  suffix-wide write would reopen the T-036 runtime matrix and is out of
  scope.
- Each additional suffix is another 389 backend and another native
  naming context. Soft reset does not drop those backends.

### Neutral / follow-up

- Schema, examples, OpenAPI, MCP catalog, and compatibility notes land
  with this change.
- Dual-engine integration covers regional suffix create, nested OUs,
  exact service-user DNs, memberOf, search base, and rejected
  unmanaged DNs.
- Native `container` stays an alias until a later schema ADR adds a
  real AD class (not required for #5).

## Alternatives considered

| Option | Why not chosen |
| --- | --- |
| Raw LDAP modify / pass-through | Forbidden by `AGENTS.md` and the first-release contract. |
| Nested additional suffixes under the primary | 389 cannot host a nested suffix in the same backend without a different mapping-tree model; sibling suffixes match `--create-suffix`. |
| Single suffix with `dc=regionN` children only | Does not match the requested `additionalSuffixes` path for separate `dc=regionN,dc=example,dc=net` naming contexts. Still allowed as ordinary entries when those DNs sit *under* one configured suffix. |
| Suffix-wide write on the primary | Would let runtime add/delete beside the marker and change T-036. Additional-suffix write ACIs are enough for #5. |
| Literal AD `container` class | Neither 389 2.4.6 nor the native LabLDAP-surface schema publishes it. Alias to `organizationalUnit`. |

## Notes

- Accepted ADRs outrank other repository documents.
- Security defaults may become stricter in a minor release; insecure
  behavior must never become the silent default.
- Do not log passwords, tokens, or secret-file content. DNs in audit
  targets are identifiers, not secrets; do not concatenate untrusted
  strings into filters or DNs.
