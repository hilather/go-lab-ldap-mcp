# LabLDAP

Disposable laboratory LDAP environment: 389 Directory Server as the directory
engine, a Go control plane for REST / MCP / UI, and Docker Compose lifecycle
roles that keep Directory Manager privileges out of the long-running service.

This repository is the implementation of the LabLDAP design package. The Go
service does **not** implement the LDAP wire protocol.

| Role | Process | Privilege |
| --- | --- | --- |
| `directory` | long-running 389 DS | owns `/data` |
| `bootstrap` | one-shot `labldap-bootstrap` | Directory Manager via secret file |
| `control` | long-running `labldap` | restricted service account; no DM secret; no Docker socket |

Working names (OD-001): **LabLDAP**, `labldap`, `labldap-bootstrap`.
Module path (OD-002): `github.com/hilather/go-lab-ldap-mcp`.
No distribution license file (OD-003). Local images only (OD-004).

## Status

Milestone **M0** is in progress. First usable release is the README definition
in the design package plus every P0 task in [`TASKS.md`](https://github.com/hilather/go-lab-ldap-mcp/blob/main/TASKS.md).

Completed: **T-001–T-040, T-044–T-094**. Next: **T-041** bootstrap container image and **T-095** UI scaffold. Remaining-work design: [`docs/design/remaining-work-t035-t120.md`](https://github.com/hilather/go-lab-ldap-mcp/blob/main/docs/design/remaining-work-t035-t120.md).

## Commands

```text
go run ./cmd/labldap --help
go run ./cmd/labldap --version
go run ./cmd/labldap-bootstrap --help
make verify
```

Structured logs go to stderr. `LABLDAP_LOG_FORMAT=json` selects JSON.

`labldap serve --config FILE` wires the LDAP pool and application services.
Liveness is `GET /health` (never LDAP). Readiness is `GET /health/ready`.
`GET /metrics` is Prometheus text. Default `requireAuth` is false: bind
the listener to loopback or restrict it with network policy, or set
`spec.management.metrics.requireAuth`. Directory flags: `--ldap-url`,
`--directory-ca-file`, `--directory-host` (or `LABLDAP_LDAP_URL`,
`LABLDAP_DIRECTORY_CA_FILE`, `LABLDAP_DIRECTORY_HOST`).

`labldap mcp-stdio --config FILE` is the local MCP transport (T-093). Protocol
bytes go **only** to stdout; logs go to stderr. The process actor is the
compiled token from `LABLDAP_MCP_TOKEN` or `--token-file` (never `--token`).
Missing credentials exit without starting the protocol. Tool scopes match
`POST /mcp`. Mutation, password, reset, and export tools register only when
`spec.management.mcp.register*` is true (OD-016).

### MCP release smoke test

Use an independent official MCP client (Go SDK `mcp.Client` +
`CommandTransport` around `labldap mcp-stdio`, or Streamable HTTP
`POST /mcp` with `Authorization: Bearer`). With mutations and password
tools enabled:

1. Call `ldap_create_user` with a unique id and password.
2. `GET /api/v1/users/{id}` with the same bearer must return the user.
3. `ldapsearch` / simple bind as that DN must succeed.
4. Confirm stdout from `mcp-stdio` contains no log lines.

See `docs/toolchain.md` for version pins. `make test-integration` starts the
pinned 389 DS image (Docker required). e2e and image targets remain pending.

## Layout

See [`AGENTS.md`](https://github.com/hilather/go-lab-ldap-mcp/blob/main/AGENTS.md)
for package boundaries. Transports (`internal/api`, `internal/mcpserver`) stay
thin and call `internal/app`. `internal/config` never connects to LDAP.
`internal/web` embeds static assets only.

## Design documents

| Path | Role |
| --- | --- |
| [`docs/design/labldap-implementation-design.md`](https://github.com/hilather/go-lab-ldap-mcp/blob/main/docs/design/labldap-implementation-design.md) | Implementation contract synthesized from the design package |
| [`docs/design/remaining-work-t035-t120.md`](https://github.com/hilather/go-lab-ldap-mcp/blob/main/docs/design/remaining-work-t035-t120.md) | Remaining-work contract for T-035–T-120 |
| [`docs/01-system-architecture.md`](https://github.com/hilather/go-lab-ldap-mcp/blob/main/docs/01-system-architecture.md) | System architecture (source package) |
| [`docs/10-implementation-plan.md`](https://github.com/hilather/go-lab-ldap-mcp/blob/main/docs/10-implementation-plan.md) | Milestones M0–M8 |
| [`docs/13-open-decisions.md`](https://github.com/hilather/go-lab-ldap-mcp/blob/main/docs/13-open-decisions.md) | Owner / verification / agent defaults |
| [`TASKS.md`](https://github.com/hilather/go-lab-ldap-mcp/blob/main/TASKS.md) | T-001–T-120 backlog |
| [`docs/adr/`](https://github.com/hilather/go-lab-ldap-mcp/tree/main/docs/adr) | Title-only ADR stubs until recovered ADR text exists |

Eighteen inventoried design-package documents are absent from the source
download. Do not fabricate them. Residual gaps are listed in the
implementation design.

## Non-negotiables

1. The Go service does not implement the LDAP wire protocol.
2. 389 DS is the source of truth for users, groups, memberships, and runtime mutations.
3. The control plane must not mount the Docker socket.
4. Directory Manager credentials are bootstrap-only.
5. REST, MCP, and the UI share one application service layer and one authorization policy.
6. Static bearer tokens are an explicit lab mode.
7. Ephemeral mode uses a memory-backed `/data` mount; host swap can still persist pages.
8. Runtime reset is a soft data reset of the managed suffix.
9. First release: one managed suffix, one 389 DS instance.
10. Active Directory emulation is out of scope.

## Version baseline

- Go language `1.26` with toolchain `go1.26.5`
- MCP specification 2026-07-28; official Go SDK v1.7.0 or later
- React 19.2; Node.js 22.12 or later; pnpm
- `quay.io/389ds/dirsrv` pinned by digest (T-024; not invented here)
