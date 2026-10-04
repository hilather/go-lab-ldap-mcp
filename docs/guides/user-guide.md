# User guide

How to operate a running LabLDAP lab from the browser, REST, LDAP, and MCP.

This page assumes you already have a stack up. If not, start at
[Quick start](quickstart.md). To seed users and groups from YAML, see
[Scenario YAML](scenario.md).

## Sign-in model

LabLDAP uses **static bearer tokens** as an explicit lab mode.

| Client | How you authenticate |
| --- | --- |
| Browser | Paste the token on `/login`. The control plane exchanges it for an `HttpOnly` session cookie plus a CSRF secret held only in page memory. |
| REST / HTTP MCP | `Authorization: Bearer <token>` |
| `labldap mcp-stdio` | `LABLDAP_MCP_TOKEN` or `--token-file`. Never `--token`. |
| Direct LDAP | Simple bind as a directory user. The control-plane token is not an LDAP password. |

The shipped example token is `admin`, stored in `secrets/token-admin`, with
scopes for read, write, password, reset, export, schema, and audit.

The example scenario seeds directory user `alice` (password file
`secrets/user-alice`) in group `staff` under `dc=example,dc=test`. That
tree is YAML — [Scenario YAML](scenario.md).

## Scenario YAML

Users and groups can be declared in the LabScenario file before the lab
starts. Bootstrap writes them into the selected directory engine.

```yaml
spec:
  users:
    - id: alice
      uid: alice
      passwordFile: /run/secrets/user-alice
      enabled: true
      attributes:
        givenName: Alice
        sn: Anderson
  groups:
    - id: staff
      members:
        - user: alice
```

No inline passwords. Groups cannot be empty. User `attributes` follow the
same write rule as the user API (below): `objectClass`, option or alias
spellings of `uid`/`cn`/`sn` (`cn;lang-en`, `commonName`, `surname`,
`userid`), numeric OIDs and protected names are rejected, and two keys that
address the same attribute (`mail` and `Mail`, `ou` and
`organizationalUnitName`, `mail` and `rfc822Mailbox`, `givenName` and `gn`)
are a `duplicate_attribute` error, reported on the later name in
case-insensitive order. Second descriptors (`rfc822Mailbox`, `gn`,
`organizationalUnitName`, …) are seeded under the primary name (`mail`,
`givenName`, `ou`).
Earlier releases silently dropped some of these spellings during seeding; a
scenario that used them now fails to compile until they are removed. YAML is the compiled baseline
(`startupMode: merge`); UI / REST / MCP mutations are live until soft reset
or `make compose-reset`. Changing the file requires a re-bootstrap.

Full mapping, ACL example, and apply steps: [Scenario YAML](scenario.md).

## The browser UI

Tokens never appear in logs. A 401 does not echo token ids. The UI does not
put the bearer in `localStorage`, `sessionStorage`, IndexedDB, or the URL.

Logout and idle expiry call `DELETE /api/v1/session`. After that you sign in
again.

## The browser UI

Open https://127.0.0.1:8443/. The management cert is a lab cert — trust the
lab CA or accept the browser warning.

| Route | What it does |
| --- | --- |
| `/` | Dashboard: scenario, engine, baseline, transports, recent audit, outage state |
| `/users` | List, create, edit, enable/disable, set password, delete |
| `/groups` | List, create (needs an initial member), membership add/remove/replace |
| `/search` | Explicit-submit LDAP search. Typing does not fire a query. |
| `/tree` | Directory browser: expand the DIT, inspect a selected DN, create an allowlisted child OU/domain/container, move or delete that DN |
| `/auth-test` | Bind diagnostic. Password field clears after the attempt. |
| `/schema` | Read-only Root DSE and schema browser |
| `/audit` | In-memory audit ring, filterable, with request-id copy |
| `/export` | Authenticated LDIF download |
| `/reset` | Soft reset to the compiled baseline |
| `/diagnostics` | Secret-free component status |

### Users

Create needs an id and a password. Updates carry a **revision**; a 412 means
someone else wrote first — refresh and retry. Delete asks you to type the
exact user id.

Passwords are write-only. They are never returned by REST, MCP, or export.

### Groups

389 `groupOfNames` cannot be empty. Creating a group requires at least one
member, chosen through a bounded server search. There is no attribute-level
`PATCH` for groups in v1 — change membership with add / remove / replace.

A membership cycle is rejected and the group is left unchanged.

### Directory tree

`/tree` (Directory in the nav) browses compiled managed suffixes
(primary plus `additionalSuffixes`). Expand the tree, select a DN, and
inspect its attributes. Create allowlisted child entries
(`organizationalUnit`, `domain`, or `container` stored as
`organizationalUnit`) under the selected DN. Move or rename and delete
with a typed-DN confirm still apply to that selected DN. Create users
and groups on `/users/new` and `/groups/new` — the tree does not host
those forms. Writes outside the configured suffixes are rejected.
Multi-domain here means multiple suffixes in one lab, not an AD forest.

### Search

Submit a base, scope, filter, attribute list, and page size. The search
base may be any managed suffix or a DN under one. Attribute names
are allow-listed. `userPassword` and other forbidden names cannot be
requested. Filters also reject secret attributes, including nested assertions,
attribute options, and known OID aliases. Attribute-less extensible matches
and unknown numeric OIDs are rejected. Results expand to a redacted LDIF snippet.

Profile and structured attribute writes use attribute names. Numeric OIDs
cannot bypass password, account-state, or ACI restrictions. Use the dedicated
password and account actions for protected fields.

User writes (REST, MCP, console, and scenario YAML) share one rule: protected
and operational names in any spelling (attribute options, numeric OIDs),
every `objectClass` spelling, and any non-bare spelling of `uid`, `cn` or
`sn` are rejected with `forbidden_attribute`; bare `cn`, `sn` and `uid` stay
writable through their normal fields. Names that address the same attribute
(case variants, option order, or one of the resolved second descriptors
`userid`, `commonName`, `surname`, `organizationalUnitName`,
`domainComponent`, `organizationName`, `rfc822Mailbox`, `gn`) are a
`duplicate_attribute` error on the later name in case-insensitive order
(`givenName` + `GN` flags `GN`). User writes send a resolved second
descriptor under its primary name, so `{"rfc822Mailbox": "a@x"}` is stored
and shown as `mail` on both engines. Other second descriptors
(`localityName`, `countryName`, …) are not resolved, so do not send both
spellings of one attribute. The user view shows only spellings this rule
accepts: optioned values such as `cn;lang-en` are hidden there and managed
through the entry API, and attributes are listed under their primary names
(`cn`, `mail`, `givenname`). Because optioned values are not part of the user view, they
do not contribute to the user revision. Entry create with `inetOrgPerson` differs: it does not reject
option or alias spellings of the planned names, it drops them and writes the
planned `uid`/`cn`/`sn` values, and it keeps only the first of two names
that address the same attribute in case-insensitive order (`mail` over
`rfc822Mailbox`); protected names are still rejected. Entry create and the
replace/add operations of entry update send `rfc822Mailbox`/`gn` as
`mail`/`givenName`; entry-update delete keeps the spelling you send. On the
native engine an attribute written earlier under an alias spelling by direct
LDAP (for example `rfc822Mailbox`) is stored under that name, shown only in
the entry view, and removed with a delete of that alias row; do not use
"Replace values" on it, which writes the primary attribute instead. The
console's attribute editor refuses replace and add for every alias name
(`userid`, `commonName`, `surname`, `organizationalUnitName`,
`domainComponent`, `organizationName`, `rfc822Mailbox`, `gn`) and allows
delete only when the entry shows a row under that alias spelling. An
entry-update delete of an optioned alias with no such row
(`rfc822Mailbox;lang-en`) removes the optioned primary (`mail;lang-en`) it
wrote; a bare alias delete never removes the primary attribute on native
(parity delta D35). Search filters resolve aliases on both engines
(`(rfc822Mailbox=x)` matches `mail`); compare and search attribute lists
on native match the name literally and do not. User and account actions
share an opaque revision that changes when lock or password-expiry state
changes; refresh existing revisions after upgrading.

### Protected attribute spellings

Protected attributes (passwords, account state, ACIs, operational
attributes) are matched by attribute type, not exact name. Attribute
options (`userPassword;lang-en`, `aci;x-tag`) and known OID spellings
(`2.5.4.35`) of a protected name are rejected on user and entry writes
with `forbidden_attribute`, and password-type attributes in any spelling
are never returned by entry reads or search, or by export with
`omitSecrets` (the default). Writes that name an attribute by numeric OID
are rejected too. If a Directory Manager writes an option spelling such as
`userPassword;lang-en` directly over LDAP, the native engine stores it
hashed; 389 stores it as written (Delta D31). The same applies to any
principal with direct LDAP write access (the runtime account or an operator
ACI). Bind with that value fails on
both engines.

### Reset and export

Soft reset requires the `lab:reset` scope, the **exact** compiled scenario
name, and the current revision. Reset drains admitted directory operations,
restores primary users and groups, and removes runtime entries beneath all
configured additional suffixes while preserving suffix roots. Changed seed
password files require recompilation and bootstrap before reset; reset refuses
to apply a different password under the old baseline revision. It does not
remove the Docker volume.

Export requires `lab:export`. Passwords are omitted. Size is bounded by
`exportMaxEntries` / `exportMaxBytes`.

Hard reset — destroy the volume — is `make compose-reset` only. It is not
exposed on REST or MCP.

## REST

Base URL: `https://127.0.0.1:8443/api/v1`

```bash
TOKEN=$(tr -d '\n' < secrets/token-admin)

# List
curl -sk -H "Authorization: Bearer $TOKEN" \
  https://127.0.0.1:8443/api/v1/users

# Create
curl -sk -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"id":"bob","password":"change-me-now"}' \
  https://127.0.0.1:8443/api/v1/users

# Search
curl -sk -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"base":"dc=example,dc=test","scope":"sub","filter":"(uid=alice)"}' \
  https://127.0.0.1:8443/api/v1/search
```

Contract: [`api/openapi.yaml`](../../api/openapi.yaml).

Useful unauthenticated endpoints:

- `GET /health` — liveness. Never talks to LDAP.
- `GET /health/ready` — runtime bind, marker, revision, no reset.
- `GET /metrics` — Prometheus text. Default `requireAuth` is false; the
  compose stack binds the listener to loopback. Tighten with
  `spec.management.metrics.requireAuth` if you expose it further.

Authenticated extras: `/api/v1/diagnostics`, `/api/v1/export`,
`/api/v1/reset`, `/api/v1/audit`, `/api/v1/schema`, `/api/v1/capabilities`,
`/api/v1/baseline`.

Errors are structured problem documents. Mutations that need a revision
return **412** on conflict.

## Direct LDAP

Yes — you can authenticate against the lab as an LDAP server. The listener is
**`labldapd` by default** (or 389 DS when `engine: 389ds`), not the Go
control plane. Point clients at `127.0.0.1:3389` (StartTLS) or
`127.0.0.1:3636` (LDAPS). Do not point an LDAP client at `:8443`; that
port is HTTPS (UI / REST / MCP).

| Port | Use |
| --- | --- |
| `127.0.0.1:3389` | LDAP, StartTLS (`-ZZ`) |
| `127.0.0.1:3636` | LDAPS |

Anonymous bind is off in the example scenario. Cleartext bind is off.
StartTLS is on.

Trust the lab CA:

- default native stack (ephemeral and persistent): `secrets/tls/ca.crt`
- 389 rollback ephemeral: `secrets/tls/instance-ca.crt`
- 389 rollback persistent: `secrets/tls/ca.crt` after import

A wrong CA or SAN fails closed. That is required behavior, not a bug.

Bind as a seeded or created user, not as Directory Manager. DM is not
available to the control plane and should not be used as a client password.

Client notes: [LDAP clients](../compatibility/ldap-clients.md).

## MCP

Two transports, one catalog, same scopes as REST.

### Streamable HTTP

```
POST https://127.0.0.1:8443/mcp
Authorization: Bearer <token>
```

`GET /mcp` is 405 (no standalone SSE). MCP disabled with a valid bearer
returns 501.

### stdio

```bash
labldap mcp-stdio --config FILE --token-file secrets/token-admin
```

Protocol on **stdout** only. Logs on **stderr**. A missing token exits
before the handshake.

### Tools

On by default (when MCP is enabled):

- `ldap_search_entries`
- `ldap_get_capabilities`
- `ldap_get_baseline`
- `ldap_get_entry`
- `ldap_get_account_state`

Off until the matching `register*` flag is true:

- Users / groups: `ldap_create_user`, `ldap_update_user`, `ldap_delete_user`,
  `ldap_enable_user`, `ldap_disable_user`, `ldap_lock_user`, `ldap_unlock_user`,
  `ldap_create_group`, `ldap_delete_group`, `ldap_add_members`,
  `ldap_remove_members`, `ldap_replace_members`
- Passwords / account workflow: `ldap_set_password` (optional `mustChange`),
  `ldap_expire_password`, `ldap_clear_password_expiry`, `ldap_bind_test`
- Lab: `ldap_reset_suffix`, `ldap_export_ldif`

Bind-test outcomes include `must_change`, `locked`, and `disabled`. Disable
(`nsAccountLock`) is not the same as lock (`pwdAccountLockedTime`).

There is no `ldap_update_group` in v1. Membership tools are the update path.

Resources: `labldap://capabilities`, `labldap://baseline`,
`labldap://rootdse`, `labldap://schema`, `labldap://entry{?dn}`, and the
schema object-class / attribute templates.

Full table: [MCP catalog](../mcp/catalog.md).

## Configuration you will actually touch

The example scenario is [`config/examples/example-lab.yaml`](../../config/examples/example-lab.yaml)
and the compose copy is `deploy/compose/scenario.yaml`.

Things operators change first:

- Seeded users and groups
- Token scopes
- `spec.management.mcp.registerMutations` (and friends)
- Suffix / naming context
- Export and reset limits

Config is `labldap.dev/v1alpha1`. `internal/config` parses and compiles it.
It never opens an LDAP connection.

Secrets are files, not inline strings. `make compose-up` generates them.
Rotate with:

```bash
go run ./tools/setupsecrets --dir secrets --force
```

Then recreate the secret-prep service / stack so the control volume picks
up the new files.

### Bootstrap LDAP timeout

`spec.limits.ldapDialTimeout` defaults to `5s`. Bootstrap honors this existing
setting during readiness checks and all subsequent LDAP phases, including tree,
seed, and verification. The adapters use the configured budget for connection
establishment and LDAP requests. Set a positive duration appropriate to the
directory environment; changing this budget does not add automatic write retries.

## What not to do

- Do not put Directory Manager in the control container.
- Do not mount `/var/run/docker.sock`.
- Do not treat ephemeral tmpfs as a wipe.
- Do not expect Active Directory semantics.
- Do not hand-run `dsconf` / `ldapadd` against the engine except the
  documented TLS import path on persistent labs.
- Do not log tokens, passwords, or session ids.

When something is on fire: [Troubleshooting](../operations/troubleshooting.md).

### Account state and structured entry changes

The user detail page shows lock and password-change state. Operators with
`directory:write` can lock or unlock the account; `directory:password` permits
requiring a password change or clearing password expiry. Set password also offers
**Require password change after setting password**. Every action sends the loaded
revision and offers a refresh when the record changed.

The Directory inspector can edit an entry attribute using replace, add, or delete
with one value per line. Passwords, object classes, managed and operational
attributes, and protected suffix/container entries cannot be edited here. Move,
delete, and attribute edits preserve optimistic concurrency; refresh explicitly
after a revision conflict before retrying.

### Concurrent directory mutations

Each control process serializes directory mutations across the user, group,
and structured entry workflows before reading the live revision. Requests using
DN aliases therefore share the same mutation boundary. Waiting requests honor
cancellation and recheck their revision after earlier mutations finish.

This conservative serialization trades parallel write throughput for protection
against stale updates across workflows. Reads remain concurrent. LDAP writes
outside this control process, including another control instance, retain the
residual search-to-write race when the engine lacks assertion controls (KD-R24).
