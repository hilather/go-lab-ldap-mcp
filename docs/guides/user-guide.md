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

No inline passwords. Groups cannot be empty. YAML is the compiled baseline
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

### Search

Submit a base, scope, filter, attribute list, and page size. Attribute names
are allow-listed. `userPassword` and other forbidden names cannot be
requested. Results expand to a redacted LDIF snippet.

### Reset and export

Soft reset requires the `lab:reset` scope, the **exact** compiled scenario
name, and the current revision. It restores the baseline suffix. It does
**not** remove the Docker volume.

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

## What not to do

- Do not put Directory Manager in the control container.
- Do not mount `/var/run/docker.sock`.
- Do not treat ephemeral tmpfs as a wipe.
- Do not expect Active Directory semantics.
- Do not hand-run `dsconf` / `ldapadd` against the engine except the
  documented TLS import path on persistent labs.
- Do not log tokens, passwords, or session ids.

When something is on fire: [Troubleshooting](../operations/troubleshooting.md).
