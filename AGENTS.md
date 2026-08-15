# AGENTS.md

This file governs implementation by automated coding agents and human contributors.

## Mission

Implement LabLDAP as a safe, deterministic laboratory directory platform using the architecture and requirements in this package. The control plane is not an LDAP server. Directory data lives in a selected engine: pinned 389 Directory Server (default) or the in-repo native engine (`labldapd`). Dual-engine work follows ADR-0008, ADR-0009, and `docs/design/native-engine-parity-contract.md`.

## Required reading before changes

Before implementing a task, read:

1. `README.md`.
2. `docs/13-open-decisions.md` for safe defaults and owner-only choices.
3. `TASKS.md` for the selected task and dependencies.
4. The relevant design document under `docs/`.
5. Every accepted ADR referenced by that document.
6. The security document for any change involving credentials, authorization, LDAP writes, logging, reset, export, or browser state.

## Non-negotiable architecture rules

- Do not implement an LDAP listener or BER protocol engine in the control plane (`labldap`) or bootstrap (`labldap-bootstrap`). The sole permitted LDAP server in this repository is `cmd/labldapd` / `internal/ldapserver` (ADR-0008, ADR-0009). Production control and bootstrap binaries must not import `internal/ldapserver`.
- Do not store users, groups, or memberships in an application-only in-memory map. Directory data lives in the selected engine (389 DS or the native bbolt store).
- Do not mount `/var/run/docker.sock` into any application container.
- Do not provide Directory Manager credentials to the long-running control service.
- Do not make the REST handlers call MCP handlers or the MCP handlers call REST handlers.
- Both transports must call the same application service interfaces.
- Do not log tokens, passwords, bind credentials, session IDs, complete authorization headers, or secret-file content.
- Do not commit plaintext secrets or generated test credentials.
- Do not concatenate untrusted strings into LDAP filters, DNs, ACIs, shell commands, or URLs.
- Do not execute `dsconf`, `dsidm`, `ldapadd`, or similar commands through a shell. Use an argument vector with `exec.CommandContext`.
- Do not add a raw arbitrary LDAP modification API to the first release.
- Do not let the runtime service account write outside the configured managed suffix.
- Do not expose hard engine reset through REST or MCP.
- Do not use a floating container tag in release Compose files.

## Repository source-of-truth hierarchy

When artifacts disagree, resolve them in this order:

1. Accepted ADRs.
2. Security requirements.
3. Product requirements.
4. API contracts and configuration schema.
5. System architecture.
6. Task descriptions.
7. Existing implementation behavior.

If an implementation discovery requires a design change, write or amend an ADR before changing the public contract.

## Expected repository layout

The implementation should converge on this structure:

```text
.
|-- AGENTS.md
|-- README.md
|-- Makefile
|-- go.mod
|-- go.sum
|-- cmd/
|   |-- labldap/
|   |-- labldap-bootstrap/
|   `-- labldapd/
|-- internal/
|   |-- api/
|   |-- app/
|   |-- apperr/
|   |-- audit/
|   |-- auth/
|   |-- config/
|   |-- directory/
|   |   |-- ldapclient/
|   |   |-- ds389/
|   |   `-- native/
|   |-- ldapserver/
|   |   `-- store/
|   |-- mcpserver/
|   |-- observability/
|   |-- reset/
|   `-- web/
|-- api/
|   |-- openapi.yaml
|   `-- generated/
|-- config/
|   |-- schema/
|   `-- examples/
|-- frontend/
|-- deploy/
|   |-- compose/
|   |-- docker/
|   `-- examples/
|-- test/
|   |-- integration/
|   |-- e2e/
|   |-- compatibility/
|   |-- parity/
|   `-- fixtures/
|-- docs/
`-- tools/
```

A different layout requires an ADR and must preserve package boundaries.

## Package boundaries

- `internal/config`: parse, default, validate, normalize, hash, and compile configuration. It must not connect to LDAP.
- `internal/directory`: transport-neutral interfaces and domain types.
- `internal/directory/ldapclient`: low-level LDAP connection, escaping, controls, and error translation.
- `internal/directory/ds389`: 389 DS bootstrap and runtime LDAP adapter.
- `internal/directory/native`: native-engine bootstrap reconcilers and capability inspect. Must not import `ds389`.
- `internal/ldapserver`: native LDAPv3 listener, codec, dispatch, schema, ACI evaluation, and plugins. Must not import `internal/api`, `internal/mcpserver`, `internal/web`, `internal/auth`, or `internal/directory/ds389`.
- `internal/ldapserver/store`: bbolt entry store behind the ldapserver `Store` interface.
- `internal/apperr`: structured error taxonomy and test helpers. Leaf package; no LDAP, HTTP, or MCP imports.
- `internal/app`: use cases, policy checks, transactions, reset orchestration, and audit calls.
- `internal/api`: HTTP transport only.
- `internal/mcpserver`: MCP transport only.
- `internal/auth`: token registry, scopes, sessions, and authorization middleware.
- `internal/audit`: structured security and mutation events.
- `internal/web`: embedded static assets and SPA fallback.

Transport packages must contain no LDAP-specific business rules.

## Implementation workflow

For each task:

1. Confirm every dependency task is complete.
2. Restate the acceptance criteria in the pull request or change summary.
3. Add or update tests first when practical.
4. Implement the smallest change that satisfies the task.
5. Run formatting, linting, unit tests, and relevant integration tests.
6. Update generated files through committed generation commands, never by hand.
7. Update documentation and examples when a contract changes.
8. Mark the task complete only when all acceptance checkboxes and the global definition of done are satisfied.

If a task cannot be completed without violating an architecture rule, stop that task and create a design-decision proposal rather than working around the rule.

## Coding standards

### Go

- Use Go 1.26 language and standard-library features unless the repository toolchain specifies a newer supported version.
- Use `context.Context` on all I/O, LDAP, HTTP, subprocess, and long-running operations.
- Use `log/slog` with structured fields.
- Wrap errors with operation context while preserving error identity.
- Use typed sentinel or structured errors at application boundaries.
- Keep interfaces small and consumer-owned.
- Use dependency injection through constructors, not global variables.
- Prefer standard `net/http` and middleware composed as `http.Handler`.
- Configure HTTP server read-header, read, write, idle, and shutdown timeouts.
- Never use `panic` for expected configuration, input, network, or directory errors.
- Use constant-time comparison for static token values.
- Zero or release sensitive byte buffers where practical, while recognizing Go cannot guarantee memory erasure.

### TypeScript and React

- Enable TypeScript strict mode.
- Use generated OpenAPI types and a single API client layer.
- Use TanStack Query for server state and avoid duplicating it in global client state.
- Do not store bearer tokens in `localStorage`, `sessionStorage`, IndexedDB, URL parameters, or browser logs.
- Meet keyboard navigation, focus, labeling, contrast, and error-announcement requirements.
- Treat all server strings as untrusted content. Do not render raw HTML.

### Shell and containers

- Use POSIX shell only where required by container entrypoints.
- Use `set -eu` and explicit error handling.
- Do not pass secrets on command lines when a password-file option exists.
- Pin base images by digest in release files.
- Run the control image as a non-root user with a read-only root filesystem.

## Required commands

The repository should expose these stable commands through `make` or an equivalent task runner:

```text
make format
make lint
make generate
make test
make test-unit
make test-integration
make test-e2e
make test-security
make compose-up
make compose-down
make compose-reset
make image
make verify
```

`make verify` is the release gate and must be suitable for continuous integration.

## Test requirements

Every behavior change requires the lowest applicable test level:

- Pure parsing or mapping: unit test.
- LDAP operation or 389 DS configuration: integration test with a real 389 DS container.
- Native engine protocol or store behavior: in-process unit/integration test against `internal/ldapserver` (no Docker required until compose-native).
- Dual-engine Contract behavior: `test/parity` with 389 as oracle (see `docs/design/native-engine-parity-contract.md`).
- REST contract: OpenAPI contract and handler test.
- MCP tool: SDK-level protocol test and application-service test.
- Browser workflow: Playwright end-to-end test.
- Authorization change: positive and negative scope tests.
- Reset or export: deterministic baseline comparison test.
- Security-sensitive parser: fuzz test or property test where practical.

Mocks must not replace the real 389 DS integration suite for engine behavior.

## Definition of done for every task

A task is done only when:

- All task-specific acceptance criteria pass.
- New public behavior is documented.
- New configuration fields have defaults, validation, schema, examples, and compatibility notes.
- New API operations appear in OpenAPI and generated clients.
- New MCP operations have input schema, output schema, scopes, annotations, and tests.
- Sensitive data is covered by logging-redaction tests.
- Errors are stable and actionable.
- The implementation works in both ephemeral and persistent Compose modes when applicable.
- Contract-tier native-engine behavior has a 389 oracle case in `test/parity` unless the task is explicitly native-only infrastructure.
- `make verify` passes.
- No new high or critical vulnerability is introduced by dependency scanning.

## Change management

- Backward-compatible configuration additions may remain within the current `apiVersion`.
- Breaking configuration changes require a new `apiVersion` and migration notes.
- Breaking REST changes require a new URL version.
- Breaking MCP tool changes require a new tool name or a documented version transition.
- Security defaults may become stricter in a minor release, but insecure behavior must never become the silent default.

## Agent reporting format

At the end of each implementation task, report:

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
