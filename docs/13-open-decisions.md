# Open Decisions and Implementation Defaults

## 1. Purpose

The design is sufficiently complete to begin implementation. This ledger identifies the remaining choices that either depend on the eventual repository owner or should be verified against the implementation environment. It prevents agents from repeatedly asking about low-risk choices while preserving explicit control over legal, publishing, and compatibility decisions.

## 2. Decision classes

- **Owner decision:** an agent must not make the final public or legal choice. Private implementation may proceed using the stated temporary behavior.
- **Verification decision:** the design provides a preferred choice, but the agent must verify that it works with pinned upstream versions and record material deviations in an ADR.
- **Agent default:** the agent should use the stated choice without requesting confirmation unless implementation evidence requires a change.

## 3. Decisions

| ID | Class | Decision | Default or temporary behavior | Resolution point |
| --- | --- | --- | --- | --- |
| OD-001 | Owner | Final project and executable name. | Use `LabLDAP`, `labldap`, and `labldap-bootstrap`. A later rename must update module paths, image names, schemas, docs, and tests atomically. | Before public release; does not block T-001. |
| OD-002 | Owner | Go module path and source repository location. | When no repository URL is supplied, use `labldap.local/labldap` for private scaffolding and isolate imports so a scripted replacement is possible. Do not publish that path. | Preferably before T-001; mandatory before publishing modules or images. |
| OD-003 | Owner | Project distribution license. | Do not invent a license or add third-party text. Treat the work as privately owned until the owner selects a license. Dependency-license policy and notices still apply. | Before public distribution. |
| OD-004 | Owner | Public container registry and image namespace. | Build local images named `labldap-control:dev` and `labldap-bootstrap:dev`; do not push. | Before release automation pushes artifacts. |
| OD-005 | Agent default | Initial supported host architectures. | Support `linux/amd64` and `linux/arm64`. Document any upstream 389 DS image limitation discovered by CI. **T-116:** pinned dirsrv digest is a multi-arch list including arm64; **advertised** release architecture is `linux/amd64` only until an arm64 smoke runs. | T-108 through T-120. |
| OD-006 | Verification | Exact 389 DS image digest. | Select an official `quay.io/389ds/dirsrv` release, verify required commands and environment behavior, and pin its immutable digest. Never retain a floating release tag in release files. | T-024 and T-108. |
| OD-007 | Verification | Directory container secret injection. | Prefer direct secret-file support. When the selected image lacks a required `_FILE` convention, use a minimal reviewed entrypoint that reads `/run/secrets` and passes values without logging or command-line exposure. | T-024 through T-027. |
| OD-008 | Agent default | Go HTTP framework. | Use the standard `net/http` server and middleware model. A third-party router requires demonstrated contract or maintenance value and an ADR. | T-060. |
| OD-009 | Verification | OpenAPI generator. | Select a maintained Go generator that supports OpenAPI 3.1 or the deliberately chosen compatible subset, deterministic output, strict request validation, and generated TypeScript consumption. Pin it and add generation-drift CI. | T-060 and T-061. |
| OD-010 | Agent default | Frontend package manager. | Use `pnpm` with an exact package-manager declaration and committed lockfile. Use a supported Node LTS release in development and builder images. | T-002 and T-095. |
| OD-011 | Agent default | UI component strategy. | Use accessible semantic HTML and small headless primitives. Do not adopt a large design system before the core workflows and accessibility tests justify it. | T-095 through T-107. |
| OD-012 | Verification | Runtime metadata storage in LDAP. | Prototype a protected metadata entry beneath the managed suffix using namespaced attributes. Define and register a private OID schema before stable release if standard attributes cannot safely represent baseline revision and ownership metadata. **T-039 observed (pinned 389 2.4.6):** preferred `device` + `serialNumber`/`owner`/`destinationIndicator` is rejected; bootstrap stores namespaced `description` JSON (see `deploy/docker/dirsrv-image-contract.md`). Private OID remains an owner checkpoint before stable release. | T-021, T-039, and ADR checkpoint before release. |
| OD-013 | Agent default | Static API token representation. | Require high-entropy token secrets from files, keep only derived lookup material and the minimum comparison representation in memory, compare in constant time, and expose only a non-secret token ID. Do not persist runtime sessions. | T-019 and T-065 through T-069. |
| OD-014 | Agent default | Browser session lifetime. | Use an in-memory, opaque, cryptographically random session ID in an `HttpOnly`, `Secure` when TLS is enabled, `SameSite=Strict` cookie. Use an inactivity timeout and an absolute lifetime; make both configurable with conservative lab defaults. | T-067 through T-069. |
| OD-015 | Verification | MCP protocol and SDK versions. | Pin the official Go SDK version that supports the current selected MCP specification and execute protocol conformance tests. Record any later protocol migration as a contract change. | T-085 through T-094. |
| OD-016 | Agent default | MCP write exposure. | Register read tools by default. Register mutation, password, reset, and export tools only when enabled and always enforce their distinct scopes in the shared application layer. | T-086 through T-093. |
| OD-017 | Agent default | TLS for local labs. | Support generated development certificates and user-supplied certificates. Do not present generated certificates as production trust. LDAPS and StartTLS tests must validate trust explicitly. | T-029 through T-033. |
| OD-018 | Verification | Empty-group representation. | Reject empty groups in `v1alpha1` when using `groupOfNames`. Do not insert a fake member. A different object class or group strategy requires an ADR and compatibility tests. | T-016, T-050, and future versioning work. |
| OD-019 | Agent default | Full engine reset. | Keep full reset as an operator-side Compose command that replaces `/data`. REST and MCP expose only suffix-scoped soft reset. | T-076 through T-083 and deployment scripts. |
| OD-020 | Verification | Minimum Docker and Compose versions. | **Accepted default (T-110):** Docker Engine 24+ and Compose v2.24+ (`env_file`, health `depends_on`, tmpfs volume `uid`/`gid`/`mode`/`size`, `service_completed_successfully`, `read_only` + `cap_drop` + `no-new-privileges`). Enforced by `tools/composepreflight` and `make compose-up`. Observed: Engine 29.1.3, Compose v2.40.3 on linux/amd64. | T-108 through T-111. |
| OD-021 | Agent default | Metrics export. | Provide bounded Prometheus-compatible metrics without DNs, usernames, filters, tokens, or passwords as labels. Metrics may be disabled by configuration. | T-073 and T-114. |
| OD-022 | Owner | Whether anonymous LDAP bind is enabled in shipped examples. | Keep anonymous bind disabled in the default example. Add a clearly labeled compatibility example only when required by a lab scenario. | Before example publication. |

## 4. Decisions that must not block implementation

The following have safe defaults and should not trigger clarification during ordinary task execution:

- Naming remains LabLDAP.
- The frontend uses `pnpm` and strict TypeScript.
- The Go service uses `net/http`.
- Dual engines (`389ds` | `native`) are accepted in ADR-0008. The omitted-field default is `native` (`labldapd`) as of the 2026-08-16 ADR-0008 amendment. Explicit `engine: 389ds` remains the oracle/rollback (`make compose-up-389ds`). Security defaults are unchanged (anonymous bind off, cleartext bind off).
- Static bearer authorization is the initial remote-management mode.
- Default MCP exposure is read-only.
- Default directory anonymous bind is disabled.
- Default deployment is ephemeral, with a separate persistent Compose profile.
- Default browser state is in-memory and cookie-based, not browser storage.

## 5. Decisions that require an ADR when changed

An implementation agent must propose an ADR before changing:

- The selected directory engine or adding a second engine to the first release. **Resolved for dual engines by ADR-0008 / ADR-0009.** Further engines (OpenLDAP, Samba AD) still require an ADR.
- The source-of-truth model.
- Bootstrap and runtime privilege separation.
- The reset boundary.
- Public configuration semantics, REST versioning, or MCP tool contracts.
- The group object-class strategy.
- The metadata ownership and baseline-revision model after it is accepted.
- The token/session security model.

## 6. Verification record format

### OD-015 verification (T-085)

```text
Decision ID: OD-015
Pinned component/version/digest: github.com/modelcontextprotocol/go-sdk@v1.7.0; MCP spec 2026-07-28; StreamableHTTPOptions.Stateless=true; StreamableHTTPOptions.PropagateRequestCancellation=true
Environment tested: host Go 1.26.5 / toolchain go1.26.5
Commands or tests: go test ./internal/mcpserver ./cmd/labldap
Observed behavior: Official SDK client connects via server/discover and negotiates 2026-07-28 only when Stateless is true. Without Stateless the SDK falls back to 2025-11-25. GET /mcp is 405 (no standalone SSE). Every HTTP MCP request requires a bearer token.
Security implications: No unauthenticated SSE. Host/Origin checks and body limits wrap the SDK handler. Tools call internal/app only (KD-R8).
Result: accepted default
Related tasks: T-085, T-086, T-087, T-088
```

When resolving a verification decision, record:

```text
Decision ID: OD-XXX
Pinned component/version/digest: ...
Environment tested: ...
Commands or tests: ...
Observed behavior: ...
Security implications: ...
Result: accepted default | ADR required
Related tasks: ...
```

### OD-020 record

```text
Decision ID: OD-020
Pinned component/version/digest: Docker Engine 24.0+ / Compose v2.24+ (preferred default). Observed Engine 29.1.3, Compose v2.40.3.
Environment tested: linux/amd64
Commands or tests: tools/composepreflight; test/composecontract; make compose-up (tmpfs uid/gid/mode/size, env_file, service_completed_successfully, read_only/cap_drop/no-new-privileges)
Observed behavior: Compose v2.24+ accepts tmpfs volume driver_opts (uid=389,gid=389,mode=0750,size=2147483648). The pinned 389 DS 2.4.6 first-boot fails when tmpfs size is 512Mi (ns-slapd never writes container.inf); 2GiB succeeds. env_file, health dependencies, and control hardening fields work.
Security implications: Older Compose may ignore tmpfs options or health conditions and leave /data world-writable or start control before bootstrap.
Result: accepted default
Related tasks: T-108 T-109 T-110 T-111
```
