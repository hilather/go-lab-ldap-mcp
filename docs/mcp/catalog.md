# MCP catalog

Recorded: 2026-08-14  
Tasks: T-119 (package), T-085–T-094 (implementation)

`internal/mcpserver` is a **package stub** on this branch. The official
Go SDK is not pinned here and `/mcp` is not mounted. REST, the embedded
UI, and direct LDAP are the shipped management surfaces.

When T-085–T-094 land, this file becomes the tool catalog (name, input
schema, output schema, scopes, annotations). Until then:

| Item | Status |
| --- | --- |
| Streamable HTTP `/mcp` | not shipped |
| `labldap mcp-stdio` | not shipped |
| Read tools | not shipped |
| Mutation / password / reset / export tools | not shipped (and off by default in YAML even after they land) |

Example scenarios set `spec.management.mcp.enabled: true` so a later MCP
build can turn on without a config break. That flag does **not** imply a
live MCP server in this tree.

T-120 residual: REST + UI + LDAP acceptance is implemented. Independent
MCP protocol acceptance waits for the MCP package.
