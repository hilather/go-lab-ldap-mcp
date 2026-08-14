# Contributing to LabLDAP

Read [README.md](https://github.com/hilather/go-lab-ldap-mcp/blob/main/README.md), [AGENTS.md](https://github.com/hilather/go-lab-ldap-mcp/blob/main/AGENTS.md), and [docs/13-open-decisions.md](https://github.com/hilather/go-lab-ldap-mcp/blob/main/docs/13-open-decisions.md) before changing code. Work from [TASKS.md](https://github.com/hilather/go-lab-ldap-mcp/blob/main/TASKS.md). Accepted ADRs outrank other documents; title-only stubs under `docs/adr/*.stub.md` are **not** accepted ADRs.

## Architecture rules

These are non-negotiable:

- Do **not** implement an LDAP listener or BER / LDAP wire-protocol engine in Go. 389 DS is the directory engine.
- Do **not** store users, groups, or memberships in an application-only in-memory map.
- Do **not** mount `/var/run/docker.sock` into any application container.
- Do **not** give Directory Manager credentials to the long-running control service (`labldap`). DM secrets are bootstrap-only (`labldap-bootstrap`).
- REST and MCP must not call each other. Both call the same application service interfaces.
- Do not commit plaintext secrets or generated test credentials. Lab secrets live in untracked `/secrets/` files.

## Verify a change

Toolchain pins are in [docs/toolchain.md](https://github.com/hilather/go-lab-ldap-mcp/blob/main/docs/toolchain.md). From the repository root:

```text
make verify
```

`make verify` is the release gate. It runs `format`, `lint`, `generate`, `generate-drift`, `test-unit`, and `test-security`.

Other stable targets: `make test-integration` (real 389 DS harness; needs Docker), `make test-e2e`, `make image`, `make frontend-build`, Compose targets. e2e, image, and Compose may print `PENDING:` until those land.

Critical vulnerability, secret, and license policy is documented in [docs/security/dependency-policy.md](https://github.com/hilather/go-lab-ldap-mcp/blob/main/docs/security/dependency-policy.md) and enforced by `make test-security` (CI `security` job).

## Source versus generated files

See [docs/generated-files.md](https://github.com/hilather/go-lab-ldap-mcp/blob/main/docs/generated-files.md). `api/openapi.yaml` is the OpenAPI source and `api/generated/` must not be hand-edited. Update generated files only through committed `make generate` commands, then confirm with `make generate-drift`.

## Task reports

Every implementation task must end with the report format in [AGENTS.md](https://github.com/hilather/go-lab-ldap-mcp/blob/main/AGENTS.md) (also copied in [docs/task-report.md](https://github.com/hilather/go-lab-ldap-mcp/blob/main/docs/task-report.md)):

```text
Task: T-XXX
Result: complete | partial | blocked
Files changed: ...
Tests run: ...
Acceptance criteria: pass/fail by item
Security notes: ...
Follow-up tasks: ...
```

Do not claim completion when integration or acceptance tests were skipped.

## Public contracts

Changes to configuration, REST, MCP, or other public contracts require documentation and tests in the same change. New configuration fields need defaults, validation, schema, examples, and compatibility notes. New API operations belong in OpenAPI and generated clients. New MCP operations need input/output schema, scopes, annotations, and tests.

Breaking configuration changes require a new `apiVersion`. Breaking REST changes require a new URL version. Breaking MCP tool changes require a new tool name or a documented version transition.

If implementation discovery requires a design change, write an ADR from [docs/adr/template.md](https://github.com/hilather/go-lab-ldap-mcp/blob/main/docs/adr/template.md) before changing the public contract. Recovered or newly accepted ADRs replace stubs; do not treat stubs as decisions.

## Pull requests

Use the repository pull-request checklist. Include the task report, do not commit secrets, and keep `make verify` green.
