# Guides

Human documentation for running LabLDAP. Start here; use the design
documents under `docs/design/` only when you are changing the product.

| Guide | When to open it |
| --- | --- |
| [Quick start](quickstart.md) | First lab, first token, first search |
| [User guide](user-guide.md) | UI, REST, LDAP, MCP, reset, export |
| [Scenario YAML](scenario.md) | Declare users, groups, ACLs, and tokens |
| [Deploy](deploy.md) | Images, compose, secrets, TLS, operations |

Related:

- [Operator guide](../operations/operator-guide.md)
- [Troubleshooting](../operations/troubleshooting.md)
- [MCP catalog](../mcp/catalog.md)
- [Release notes](../release/notes.md)
- Dual-engine ADRs: [0008](../adr/0008-dual-directory-engines.md), [0009](../adr/0009-native-engine-topology-and-storage.md)
- [Native parity contract](../design/native-engine-parity-contract.md) (default engine is `native`; `389ds` is oracle/rollback)
- Public site: https://hilather.github.io/go-lab-ldap-mcp/ (GitHub Pages from this `docs/` tree)
