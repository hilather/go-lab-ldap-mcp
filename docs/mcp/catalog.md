# MCP catalog

Recorded: 2026-08-14  
Source: `internal/mcpserver/catalog.go` (`Catalog()`, `ResourceCatalog()`).  
Do not rename tools without an ADR if `docs/05-mcp-api.md` is recovered.

Streamable HTTP is `POST /mcp` (official Go SDK `v1.7.0`, protocol
2026-07-28, `Stateless: true`). Local transport: `labldap mcp-stdio`
(protocol on stdout, logs on stderr). Every HTTP MCP request requires a
bearer from the same token registry as REST.

Read tools register when `spec.management.mcp.enabled` is true (default
in shipped examples). Mutation, password, reset, and export tools
register only when the matching `register*` flag is true (OD-016).

## Tools

| Name | Contract | Task | Scope | Default | Notes |
| --- | --- | --- | --- | --- | --- |
| `ldap_search_entries` | binding | T-088 | `directory:read` | on | Input/output match `POST /api/v1/search`. `approxMatch` (`~=`) is rejected as `filter` / `unsupported_filter` (HTTP 400); direct LDAP `~=` remains D15. |
| `ldap_get_capabilities` | proposed | T-088 | `directory:read` | on | `GET /api/v1/capabilities` |
| `ldap_get_baseline` | proposed | T-088 | `directory:read` | on | `GET /api/v1/baseline` |
| `ldap_get_entry` | proposed | T-088 | `directory:read` | on | Base-scope read; passwords stripped |
| `ldap_create_user` | proposed | T-089 | `directory:write` | `registerMutations` | Sensitive: `password` |
| `ldap_update_user` | proposed | T-089 | `directory:write` | `registerMutations` | Requires `revision` |
| `ldap_delete_user` | proposed | T-089 | `directory:write` | `registerMutations` | Destructive; `confirm` + `revision` |
| `ldap_set_password` | proposed | T-089 | `directory:password` | `registerPassword` | Sensitive: `password` |
| `ldap_create_group` | proposed | T-090 | `directory:write` | `registerMutations` | Empty members is `empty_group` |
| `ldap_delete_group` | proposed | T-090 | `directory:write` | `registerMutations` | Destructive; `confirm` + `revision` |
| `ldap_add_members` | proposed | T-090 | `directory:write` | `registerMutations` | |
| `ldap_remove_members` | proposed | T-090 | `directory:write` | `registerMutations` | |
| `ldap_replace_members` | proposed | T-090 | `directory:write` | `registerMutations` | Empty replacement is `empty_group` |
| `ldap_bind_test` | proposed | T-091 | `directory:password` | `registerPassword` | Unknown user ≡ wrong password |
| `ldap_reset_suffix` | proposed | T-092 | `lab:reset` | `registerReset` | Destructive; name + revision + confirm |
| `ldap_export_ldif` | proposed | T-092 | `lab:export` | `registerExport` | Small inline; large → REST handoff |

`ldap_update_group` is **omitted** in v1 (no `PATCH /api/v1/groups/{id}`;
membership tools are the update path).

## Resources

| URI / template | Scope | Sibling tool |
| --- | --- | --- |
| `labldap://capabilities` | `directory:read` | `ldap_get_capabilities` |
| `labldap://baseline` | `directory:read` | `ldap_get_baseline` |
| `labldap://rootdse` | `schema:read` | (T-070) |
| `labldap://schema` | `schema:read` | (T-070) |
| `labldap://schema/objectclass/{name}` | `schema:read` | (T-070) |
| `labldap://schema/attribute/{name}` | `schema:read` | (T-070) |
| `labldap://entry{?dn}` | `directory:read` | `ldap_get_entry` |

## Operator notes

- Disabled MCP: valid bearer on `POST /mcp` returns **501**.
- GET `/mcp` is **405** (no standalone SSE).
- REST, MCP, and UI share `internal/app` and the same scopes.
