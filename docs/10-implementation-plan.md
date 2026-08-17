# Implementation Plan

## 1. Delivery approach

Implement LabLDAP in dependency order, proving each risky boundary with executable tests before adding presentation layers. The critical path is configuration compiler -> real 389 DS bootstrap -> restricted runtime access -> shared application services -> transports -> UI -> release hardening.

The detailed issue backlog is in `../TASKS.md`. This plan groups those tasks into milestones with explicit exit criteria.

## 2. Milestone overview

| Milestone | Task range | Outcome |
| --- | --- | --- |
| M0 - Repository and quality foundation | T-001 to T-008 | Reproducible repository, toolchain, CI, generation, logging, errors, and security scans. |
| M1 - Configuration compiler | T-009 to T-023 | Strict YAML config compiles deterministically to validated engine and data plans. |
| M2 - 389 DS bootstrap | T-024 to T-044 | Empty real 389 DS container becomes a verified seeded directory with restricted runtime identity. |
| M3 - Runtime directory and application services | T-045 to T-059 | Transport-neutral user, group, search, schema, bind, revision, and capability services. |
| M4 - REST, authentication, security, audit, and health | T-060 to T-075 | Secured REST API and browser session foundation with observability and contract tests. |
| M5 - Reset and export | T-076 to T-084 | Deterministic soft reset, status, recovery, and redacted streaming LDIF export. |
| M6 - MCP | T-085 to T-094 | Official-SDK Streamable HTTP and stdio MCP surfaces over the shared services. |
| M7 - Web UI | T-095 to T-107 | Reactive, accessible UI covering all supported workflows. |
| M8 - Deployment and release | T-108 to T-120 | Hardened images, Compose profiles, setup tools, compatibility evidence, and release package. |
| M9 - Native Go engine and dual-mode parity | T-121 to T-150 | `labldapd` with LabLDAP-surface parity vs 389 DS (ADR-0008). |

## 3. Milestone M0 - Repository and quality foundation

### Objective

Create a repository in which every later artifact can be generated, tested, scanned, and reproduced.

### Deliverables

- Go module and command skeletons.
- Frontend workspace placeholder.
- Make targets and tool pinning.
- CI jobs for static, unit, contract, integration placeholders, and image build.
- Structured logging, build information, error types, and request IDs.
- Dependency, secret, and license scanning.

### Exit criteria

- `make format`, `make lint`, `make generate`, `make test-unit`, and `make verify` execute successfully, even where integration jobs contain explicit pending gates.
- Toolchain and dependencies are pinned.
- Generated-file checks detect drift.
- No plaintext test secrets are committed.
- Command skeletons shut down cleanly.

### Risks retired

- Repository drift.
- Unreproducible code generation.
- Inconsistent logging and error behavior.
- Late discovery of toolchain incompatibility.

## 4. Milestone M1 - Configuration compiler

### Objective

Turn a strict versioned YAML scenario into an immutable normalized model, engine plan, data plan, and stable revisions without connecting to LDAP.

### Deliverables

- Public Go config types and JSON Schema.
- Strict parser and version conversion.
- DN, attribute, secret, duration, transport, scope, user, group, and ACL validation.
- User and group reference resolution.
- ACI compiler with golden tests.
- Normalized redacted JSON.
- Directory baseline and control revision hashing.
- Example configs and plan CLI.
- Fuzzing corpus.

### Exit criteria

- Every configuration example validates.
- Unknown fields fail.
- Invalid scenarios report multiple field paths and stable codes.
- Normalization is deterministic under randomized map order.
- Password secret changes alter the directory baseline revision.
- Management token changes alter the control revision without altering directory data revision.
- ACI compiler passes injection and golden tests.

### Risks retired

- Ambiguous configuration semantics.
- Non-deterministic reset baseline.
- Unsafe string-based ACI generation.
- Secret leakage through diagnostics.

## 5. Milestone M2 - 389 DS bootstrap

### Objective

Prove the selected engine and privilege separation against a real pinned 389 DS container.

### Deliverables

- Real-engine test harness.
- Generated lab CA and server certificate fixtures.
- Bootstrap executable and phase reporting.
- Engine readiness probe and inspection.
- Backend creation and conflict detection.
- TLS, authentication, plugin, password-policy, and index reconciliation.
- Base tree, service account, ACI, users, groups, memberships, and metadata marker apply.
- Reset, merge, and validate bootstrap modes.
- Runtime allow and deny verification.
- Initial Compose dependency topology.

### Exit criteria

- A fresh empty container becomes a working directory from one command.
- A second identical apply is idempotent.
- Runtime account can perform intended data CRUD and cannot modify `cn=config`.
- MemberOf and referential integrity work.
- Password policy and lockout tests pass.
- The marker is written only after verification.
- Control service does not need Directory Manager credentials.

### Risks retired

- Upstream container incompatibility.
- Unsupported `dsconf` assumptions.
- Incorrect plugin and policy mapping.
- Overbroad runtime ACIs.

## 6. Milestone M3 - Runtime directory and application services

### Objective

Implement a transport-neutral service layer backed by the restricted LDAP identity.

### Deliverables

- Directory interfaces and structured error taxonomy.
- TLS LDAP connection factory and bounded pool.
- User and group repositories.
- Membership, search, schema, Root DSE, bind-test, and capability adapters.
- Entry revisions and optimistic preconditions.
- Application services with scopes, validation, audit hooks, and mutation coordination.
- Unit and real-engine integration tests.

### Exit criteria

- Every supported domain operation works through application services without HTTP or MCP.
- Bind tests use disposable connections.
- Connection failures recover without leaks.
- Direct LDAP changes are observed after a fresh read.
- Operational and secret attributes are filtered.
- Revision conflicts are detected.

### Risks retired

- Transport-to-LDAP coupling.
- Connection pool leaks.
- Unsafe bind-test reuse.
- Inconsistent error mapping.

## 7. Milestone M4 - REST, authentication, security, audit, and health

### Objective

Expose a secure, versioned management API and session foundation suitable for the UI.

### Deliverables

- Complete OpenAPI contract.
- HTTP server with timeouts, request IDs, recovery, body limits, and graceful shutdown.
- Static token registry and scope middleware.
- Browser session store, cookies, CSRF, Origin, CORS, and security headers.
- User, group, membership, search, bind-test, schema, capabilities, baseline, session, audit, and health endpoints.
- Pagination and protected cursors.
- Rate limits.
- Structured audit and metrics.
- Contract, scope, security, and redaction tests.

### Exit criteria

- Every OpenAPI operation has an implementation and schema-valid response.
- Read-only token cannot mutate.
- Password scope is independent of write scope.
- Session login does not persist the token in the browser contract.
- CSRF and Origin negative tests pass.
- Logs and audit output contain no test token or password.
- Liveness remains healthy during directory outage while readiness fails.

### Risks retired

- Authentication bypass.
- Scope drift across routes.
- Browser token leakage.
- Unbounded requests and searches.
- Inconsistent API contract.

## 8. Milestone M5 - Reset and export

### Objective

Deliver the core lab lifecycle differentiators with deterministic behavior and recovery evidence.

### Deliverables

- Exclusive mutation gate and reset state machine.
- Inventory and dependency-safe delete plan.
- Baseline reapply using restricted identity and seed secrets.
- Verification and marker update.
- Reset operation status through application and REST.
- Streaming deterministic LDIF encoder and redaction.
- Failure injection and restart recovery tests.

### Exit criteria

- Reset restores the baseline after REST, MCP-ready application, and direct LDAP mutations.
- Reset requires `lab:reset`, expected revision, and exact scenario confirmation.
- Partial failure leaves marker uncommitted and readiness false.
- Export streams within memory bounds and omits passwords.
- Reset and export are fully audited.

### Risks retired

- Partial reset corruption.
- Secret requirements for password restoration.
- Unbounded export memory.
- Accidental destructive operation.

## 9. Milestone M6 - MCP

### Objective

Expose agent-friendly operations using the current official SDK without duplicating business logic.

### Deliverables

- Official SDK pin and protocol-version record.
- Streamable HTTP mount behind bearer authorization.
- Central tool catalog and metadata validation.
- Read, user, group, membership, bind-test, baseline, reset, and export tools.
- Read-only resources.
- Optional stdio command.
- SDK client, scope, cancellation, and real-engine tests.

### Exit criteria

- SDK client initializes, lists, and calls tools.
- Every HTTP MCP request requires authorization.
- Tool scope matrix matches REST application services.
- Destructive tools require confirmation and metadata.
- No legacy unauthenticated SSE endpoint exists.
- Stdio writes protocol only to stdout.

### Risks retired

- MCP transport drift.
- Separate authorization implementations.
- Tool schemas leaking credentials.
- REST-as-internal-API anti-pattern.

## 10. Milestone M7 - Web UI

### Objective

Provide a practical, accessible operator experience over the REST contract.

### Deliverables

- React workspace and generated API client.
- Session login and logout.
- Application shell, dashboard, and degraded state.
- User and group workflows.
- Membership management.
- Search, bind test, schema, audit, export, reset, and diagnostics.
- Conflict handling, scope explanations, and reset progress.
- Accessibility, component, security, and Playwright tests.

### Exit criteria

- Administrator can complete the product acceptance scenario in the browser.
- Read-only actor sees and receives correct authorization behavior.
- Token is absent from browser storage after login.
- Password inputs are cleared.
- Core workflows meet accessibility checks.
- Reset clears caches and displays verified baseline state.

### Risks retired

- UI/API contract drift.
- Unsafe token handling.
- Inaccessible destructive workflows.
- Stale state overwrites.

## 11. Milestone M8 - Deployment and release

### Objective

Package, harden, verify, and document a reproducible release.

### Deliverables

- Control and bootstrap Dockerfiles.
- Pinned 389 DS image and Compose manifests.
- Ephemeral and persistent profiles.
- Secret and TLS setup helpers.
- Operational commands and troubleshooting.
- Multi-architecture builds where supported.
- SBOM, scans, provenance, and checksums.
- Performance limits and compatibility report.
- Release and upgrade documentation.

### Exit criteria

- Fresh ephemeral and persistent deployments pass.
- Persistent restart preserves runtime state.
- Ephemeral recreation restores baseline and removes runtime state.
- Control runs non-root, read-only, without Docker socket or DM secret.
- Images and Compose references are pinned.
- Release security gates have no unapproved critical findings.
- Complete acceptance scenario passes through REST, MCP, UI, and direct LDAP.

## 11a. Milestone M9 - Native Go engine and dual-mode parity

### Objective

Ship `labldapd` as a selectable directory engine with LabLDAP-surface parity against 389 DS (oracle), without putting an LDAP listener in the control plane.

### Deliverables

- ADR-0008 / ADR-0009 and the parity contract (T-121).
- `internal/ldapserver` + bbolt store + `cmd/labldapd`.
- Native bootstrap reconcilers and `make compose-up-native`.
- `test/parity` dual-engine harness.

### Exit criteria

- Contract-tier cases in `docs/design/native-engine-parity-contract.md` pass against both engines.
- `labldap` / `labldap-bootstrap` do not import `internal/ldapserver`.
- Default `engine: 389ds` behavior is unchanged through M9. **v0.3.0** (2026-08-17) flips the omitted-field default to `native`; explicit `engine: 389ds` remains the oracle.
- Native mode is not advertised as ready until T-150.

## 12. Critical path

```text
T-001 -> T-009 -> T-014 -> T-020 -> T-024 -> T-029 -> T-034 -> T-041
      -> T-045 -> T-049 -> T-054 -> T-060 -> T-064 -> T-069 -> T-076
      -> T-080 -> T-085 -> T-089 -> T-095 -> T-099 -> T-108 -> T-120
M9:   T-121 -> T-122 -> T-124 -> T-125 -> T-128 -> T-135 -> T-139
      -> T-143 -> T-144 -> T-147 -> T-150
```

The exact task descriptions and dependencies are in `TASKS.md`.

## 13. Parallel work opportunities

After M1 contracts stabilize:

- Frontend scaffolding can begin against generated mock OpenAPI, but feature completion waits for REST contracts.
- Security test harness can be built in parallel with engine adapter work.
- Documentation and setup helper design can proceed alongside runtime services.
- MCP catalog schema work can begin after application commands stabilize.

Avoid parallel implementation of user semantics in REST, MCP, and UI before the domain model is accepted.

## 14. Agent execution strategy

A single implementation agent should:

1. Select the lowest-numbered ready P0 task.
2. Complete dependencies and tests before advancing.
3. Keep changes small enough that acceptance criteria remain attributable.
4. Update task status and design docs in the same change when implementation discoveries alter assumptions.
5. Run the relevant milestone gate after each task and `make verify` at milestone completion.

Multiple agents should own separate packages only after public interfaces and generated contracts are merged. Do not have separate agents invent overlapping user, group, auth, or error models.

M9 (native engine) is designed for parallel cloud agents after **T-122** merges. Follow the wave table in `TASKS.md` §M9. Do not farm T-124+ until `Codec`, `Store`, `Schema`, `ACIEngine`, and `Server` interfaces are on `main`. Best-of-2 is appropriate for T-124 (BER) and T-138 (ACI parser). Keep Delta adjudication (T-147 failures that might be Deltas) local.

## 15. Design review checkpoints

Conduct explicit review at:

- End of M1: configuration and ACL contract.
- End of M2: engine mapping and privilege proof.
- End of M4: REST, token, session, and audit security.
- End of M5: reset failure behavior.
- End of M6: MCP spec conformance.
- End of M7: UI security and accessibility.
- End of M8: release evidence.
- End of M9: native engine Contract parity vs 389; privilege separation still holds; `labldap` does not import `internal/ldapserver`.

## 16. Completion definition

The project is implementation-complete only when all P0 and P1 tasks in `TASKS.md` are complete, every milestone exit criterion passes, and the end-to-end product acceptance scenario in the product requirements is captured as an automated release test.
