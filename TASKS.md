# LabLDAP Implementation Backlog

## How to use this backlog

- Work in numeric order unless a task's dependencies permit safe parallel work.
- Read `AGENTS.md` and the linked design documents before implementation.
- Mark a task complete only when every acceptance item and the global definition of done pass.
- `P0` tasks are required for the first usable release. `P1` tasks are required for a polished release unless explicitly deferred through an ADR.
- Size is relative implementation complexity: S, M, or L. It is not a time estimate.

## Status legend

- `[ ]` Not started.
- `[~]` In progress.
- `[x]` Complete.
- `[!]` Blocked; add a reason and blocking decision.

## Milestone index

| Milestone | Tasks | Gate |
| --- | --- | --- |
| M0 Repository foundation | T-001 to T-008 | Reproducible static and unit pipeline. |
| M1 Configuration compiler | T-009 to T-023 | Deterministic validated plans and revisions. |
| M2 389 DS bootstrap | T-024 to T-044 | Verified engine and least-privilege runtime identity. |
| M3 Runtime services | T-045 to T-059 | Transport-neutral domain operations on real 389 DS. |
| M4 REST and security | T-060 to T-075 | Secured OpenAPI implementation and auditability. |
| M5 Reset and export | T-076 to T-084 | Deterministic reset and redacted streaming export. |
| M6 MCP | T-085 to T-094 | Official-SDK MCP server over shared services. |
| M7 Web UI | T-095 to T-107 | Complete operator workflows and accessibility. |
| M8 Deployment and release | T-108 to T-120 | Hardened reproducible release package. |
| M9 Native Go engine and dual-mode parity | T-121 to T-150 | `labldapd` + LabLDAP-surface parity vs 389 DS (ADR-0008). |

# M0 - Repository and quality foundation

## [x] T-001 Scaffold repository and package boundaries

Priority: P0 | Size: M | Depends on: none

Deliverables: Go module, `cmd/labldap`, `cmd/labldap-bootstrap`, internal package skeleton, frontend directory, API/config/deploy/test directories, root README and AGENTS copy.

Acceptance:
- [x] Both commands compile and return useful `--help` output.
- [x] Package layout follows `AGENTS.md` or an accepted replacement ADR.
- [x] No application package imports HTTP and MCP transport types together.

## [x] T-002 Pin toolchains and initial dependency policy

Priority: P0 | Size: S | Depends on: T-001

Deliverables: Go toolchain version, Node version, package manager lock file, dependency update policy, and pinned developer tools.

Acceptance:
- [x] Go and frontend builds are reproducible from clean caches.
- [x] Exact tool versions are discoverable through committed files.
- [x] Version choices are documented against the design baseline.

## [x] T-003 Create Makefile and tool bootstrap commands

Priority: P0 | Size: M | Depends on: T-001, T-002

Deliverables: stable targets from `AGENTS.md`, local tool installation strategy, and help output.

Acceptance:
- [x] `make format`, `lint`, `generate`, `test-unit`, `test-integration`, `test-e2e`, `image`, and `verify` exist.
- [x] Tool installation does not silently use floating versions.
- [x] Commands work from repository root on a clean environment.

## [x] T-004 Establish continuous integration baseline

Priority: P0 | Size: M | Depends on: T-003

Deliverables: static, Go unit, frontend unit, contract, integration placeholder, image, and security jobs.

Acceptance:
- [x] Pull requests run formatting, linting, unit tests, and generated-drift checks.
- [x] Main branch can require integration and image gates.
- [x] CI caches do not contain committed credentials or expose secret values.

## [x] T-005 Implement structured logging, build information, and request IDs

Priority: P0 | Size: M | Depends on: T-001

Deliverables: `slog` configuration, human and JSON modes, build version structure, request or operation ID generator, and context propagation helpers.

Acceptance:
- [x] Both commands emit structured component and version fields.
- [x] Request IDs can propagate from HTTP or MCP into application and LDAP logs.
- [x] A redaction test proves known sensitive value types do not stringify normally.

## [x] T-006 Define error taxonomy and test utilities

Priority: P0 | Size: M | Depends on: T-001

Deliverables: structured application errors, field errors, retryability, test assertions, fakes, and golden-file helpers.

Acceptance:
- [x] Error identity survives wrapping.
- [x] Error codes cover configuration, auth, directory, reset, export, and bootstrap categories.
- [x] Tests can assert code, fields, cause, and safe public message independently.

## [x] T-007 Add security, secret, vulnerability, and license scans

Priority: P0 | Size: M | Depends on: T-002, T-004

Deliverables: Go vulnerability scan, frontend audit, secret scan, container scan placeholder, and license policy.

Acceptance:
- [x] CI fails on committed high-confidence secrets.
- [x] Critical vulnerability policy is documented and enforced.
- [x] Scan output is retained without exposing private registry credentials.

## [x] T-008 Add contribution, task-status, generation, and ADR workflow

Priority: P1 | Size: S | Depends on: T-001, T-003

Deliverables: contribution guide, generated-file policy, task completion template, ADR template, and pull-request checklist.

Acceptance:
- [x] Contributors can identify source versus generated files.
- [x] Public contract changes require documentation and tests.
- [x] Task reports use the format in `AGENTS.md`.

# M1 - Configuration compiler

## [x] T-009 Define public configuration types and version registry

Priority: P0 | Size: M | Depends on: T-001, T-006

Deliverables: `v1alpha1` Go types, `apiVersion` and `kind` dispatch, internal normalized-model types, and conversion interface.

Acceptance:
- [x] Unsupported versions and kinds return stable errors.
- [x] Public YAML types are separate from immutable normalized types.
- [x] Sensitive fields use explicit secret-reference types.

## [x] T-010 Create machine-readable configuration JSON Schema

Priority: P0 | Size: M | Depends on: T-009

Deliverables: JSON Schema for `v1alpha1`, validation command, and schema-generation or synchronization strategy.

Acceptance:
- [x] Valid examples pass and invalid fixtures fail at expected paths.
- [x] Unknown behavior fields are rejected.
- [x] Schema enums match Go constants through a drift test.

## [x] T-011 Implement strict YAML parsing and version conversion

Priority: P0 | Size: M | Depends on: T-009, T-010

Deliverables: strict decoder, duplicate-key detection, unknown-field rejection, source-path diagnostics, and conversion to internal input model.

Acceptance:
- [x] Trailing YAML documents and duplicate keys fail.
- [x] Multiple independent parse or conversion errors are reported where possible.
- [x] No secret value appears in parse diagnostics.

## [x] T-012 Validate transport, authentication, lifecycle, limits, and management settings

Priority: P0 | Size: L | Depends on: T-011

Deliverables: defaulting and semantic validation for non-directory-object configuration.

Acceptance:
- [x] Secure transport is required unless explicit insecure lab mode is enabled.
- [x] Duration, port, address, page, body, concurrency, and rate limits are bounded.
- [x] Startup and storage modes produce coherent warnings or errors.

## [x] T-013 Implement DN, RDN, attribute-name, and value normalization

Priority: P0 | Size: L | Depends on: T-011

Deliverables: canonical DN wrapper, safe RDN builder, descendant checks, attribute-name normalization, value-size rules, and operational-attribute deny list.

Acceptance:
- [x] Generated DNs safely escape arbitrary valid IDs.
- [x] Descendant checks are structural rather than string suffix checks.
- [x] Unicode, escaped comma, plus, equals, leading space, and NUL cases are tested.

## [x] T-014 Implement file secret resolver and sensitive-value handling

Priority: P0 | Size: M | Depends on: T-006, T-011

Deliverables: file resolver, trailing-newline rule, digest, redacted representation, duplicate and empty detection helpers.

Acceptance:
- [x] Errors show logical owner and path but not content.
- [x] Secret digests are stable.
- [x] Logging or formatting a secret yields only redacted output.

## [x] T-015 Normalize and validate users

Priority: P0 | Size: L | Depends on: T-013, T-014

Deliverables: user defaults, generated DN, required object classes and attributes, password reference resolution, enablement model, duplicate detection, and managed-field set.

Acceptance:
- [x] Explicit ID, uid, RDN, and DN inconsistencies fail.
- [x] `userPassword`, `memberOf`, and operational attributes cannot be supplied in normal attributes.
- [x] Normalized users are canonically ordered and immutable.

## [x] T-016 Normalize and validate groups and memberships

Priority: P0 | Size: L | Depends on: T-013, T-015

Deliverables: static DN group model, generated DN, user and group reference resolution, duplicate removal, nesting-cycle detection, and member ordering.

Acceptance:
- [x] Empty `groupOfNames` groups fail with a specific error.
- [x] Missing and circular member references fail with source paths.
- [x] Nested-group behavior follows the configured flag.

## [x] T-017 Compile and validate portable password policy

Priority: P0 | Size: M | Depends on: T-012

Deliverables: normalized policy model, cross-field validation, supported storage-scheme allowlist, and adapter-facing plan.

Acceptance:
- [x] Warning age cannot exceed maximum age.
- [x] Lockout values are required and positive when enabled.
- [x] Unsupported fields or schemes fail rather than being ignored.

## [x] T-018 Implement ACL DSL and deterministic 389 DS ACI compiler

Priority: P0 | Size: L | Depends on: T-013, T-015, T-016

Deliverables: principal, target, permission, attribute, and condition model; safe ACI emitter; raw-ACI gate; golden fixtures.

Acceptance:
- [x] Generated ACIs are deterministic and named by stable ACL ID.
- [x] DNs, filters, attributes, and names cannot inject ACI clauses.
- [x] Runtime service cannot be granted `cn=config` access through normal DSL.

## [x] T-019 Normalize management tokens and scopes

Priority: P0 | Size: M | Depends on: T-012, T-014

Deliverables: token definition validation, known scope registry, duplicate token-value detection, and redacted normalized token metadata.

Acceptance:
- [x] Duplicate IDs, duplicate values, empty tokens, and unknown scopes fail.
- [x] `directory:write` does not imply password, reset, or export scopes.
- [x] Printable configuration never contains raw tokens.

## [x] T-020 Generate deterministic engine and data plans

Priority: P0 | Size: L | Depends on: T-015, T-016, T-017, T-018, T-019

Deliverables: engine plan, data plan, create/update/delete ordering, preserved-entry list, managed-field ownership, and redacted plan rendering.

Acceptance:
- [x] Parents precede children on create and reverse on delete.
- [x] Runtime service account and marker handling are explicit.
- [x] Repeated compilation produces byte-identical redacted plans.

## [x] T-021 Implement directory baseline and control configuration revisions

Priority: P0 | Size: M | Depends on: T-014, T-020

Deliverables: canonical JSON encoder, compiler-contract version, directory revision, control revision, and revision diagnostics.

Acceptance:
- [x] Input map order does not change either revision.
- [x] Seed password change changes directory revision.
- [x] Management-token value or scope change changes control revision without changing directory revision when directory data is unchanged.

## [x] T-022 Add configuration validate, normalize, and plan CLI commands

Priority: P0 | Size: M | Depends on: T-020, T-021

Deliverables: command output in human and JSON modes, redaction, exit codes, example invocation, and drift-ready plan format.

Acceptance:
- [x] Invalid configuration exits non-zero with all safe diagnostics.
- [x] `--redact` is default and no option prints passwords or tokens.
- [x] JSON output is stable enough for CI use.

## [x] T-023 Build configuration golden, property, and fuzz test suite

Priority: P0 | Size: L | Depends on: T-010 to T-022

Deliverables: valid and invalid fixtures, golden normalized models and ACIs, randomized ordering properties, and fuzz corpora.

Acceptance:
- [x] Fuzz targets cover YAML, DN, filter, ACI, and cursor-ready primitives.
- [x] Secret corpus values are scanned from test output and absent.
- [x] `make test-unit` runs all deterministic configuration checks.

# M2 - 389 DS bootstrap

## [x] T-024 Pin and document the 389 DS image contract

Priority: P0 | Size: M | Depends on: T-002, T-007

Deliverables: immutable image digest, version, architecture manifest, entrypoint inspection, ports, `/data` behavior, available CLI tools, user IDs, and secret-input findings.

Acceptance:
- [x] Image digest and observed contract are committed to a versioned file.
- [x] Floating tags are absent from release-oriented files.
- [x] Any divergence from upstream documentation is recorded.

## [x] T-025 Implement the real 389 DS integration harness

Priority: P0 | Size: L | Depends on: T-003, T-024

Deliverables: container lifecycle helper, isolated network and state, log capture, cleanup, random ports, and CI support.

Acceptance:
- [x] A test starts the pinned image and confirms process health.
- [x] Failures attach redacted directory logs.
- [x] Repeated runs do not leak containers, networks, volumes, or ports.

## [x] T-026 Generate test CA and directory TLS certificates

Priority: P0 | Size: M | Depends on: T-025

Deliverables: test-only CA helper, SAN certificate generation, trust mount, wrong-CA and wrong-name fixtures.

Acceptance:
- [x] LDAPS succeeds with correct trust and name.
- [x] Wrong CA and wrong server name fail closed.
- [x] Private key values never appear in test logs.

## [x] T-027 Implement bootstrap command and phase reporting

Priority: P0 | Size: M | Depends on: T-005, T-006, T-022, T-025

Deliverables: `apply`, `validate`, and `plan` commands, phase state, deadlines, JSON summary, and exit codes.

Acceptance:
- [x] Every phase reports duration and safe counts.
- [x] Any failed phase produces non-zero exit and stable code.
- [x] Directory Manager password is accepted through a file, not a command-line value.

## [x] T-028 Implement engine wait, TLS probe, and administrative bind

Priority: P0 | Size: M | Depends on: T-026, T-027

Deliverables: bounded retry with jitter, Root DSE probe, LDAPS or StartTLS setup, DM bind, and cancellation.

Acceptance:
- [x] Engine startup delay is tolerated within configured deadline.
- [x] Certificate and bind failures are distinguished safely.
- [x] Cancellation stops retry promptly.

## [x] T-029 Inspect and reconcile backend and suffix

Priority: P0 | Size: L | Depends on: T-024, T-028

Deliverables: `dsconf` runner using argument vectors and password file, JSON output parser, backend create or verify, conflict detection, and index-plan hook.

Acceptance:
- [x] Fresh backend is created with configured suffix.
- [x] Matching existing backend is accepted.
- [x] Name or suffix conflicts fail without repurposing data.

## [x] T-030 Reconcile engine TLS and authentication settings

Priority: P0 | Size: L | Depends on: T-028, T-029

Deliverables: adapter plan for anonymous bind, secure simple bind expectations, LDAPS, StartTLS, and required SASL capability verification.

Acceptance:
- [x] Configured LDAP transports are verified from a client connection.
- [x] Cleartext simple bind is rejected when disabled.
- [x] Required unsupported SASL mechanisms fail bootstrap.

## [x] T-031 Reconcile and verify global password policy

Priority: P0 | Size: L | Depends on: T-017, T-029

Deliverables: versioned field mapping, `dsconf pwpolicy` application, read-back verification, and policy integration fixtures.

Acceptance:
- [x] Every public policy field is either applied and verified or rejected as unsupported.
- [x] Minimum length, history, maximum age configuration, and lockout behavior have real-engine tests.
- [x] Passwords are never passed on command lines or logged.

## [x] T-032 Configure MemberOf, referential integrity, and account disablement

Priority: P0 | Size: L | Depends on: T-029

Deliverables: plugin inspection, enablement, scope configuration, fix-up invocation, referential behavior, and adapter-selected account disable mechanism.

Acceptance:
- [x] Membership changes update `memberOf` as documented.
- [x] User deletion removes or repairs group references.
- [x] Administrative disablement prevents bind without deleting the entry.

## [x] T-033 Create base tree and runtime service account

Priority: P0 | Size: M | Depends on: T-015, T-020, T-029

Deliverables: suffix root and containers, runtime account entry, secure password set, and stable DN mapping.

Acceptance:
- [x] Parent creation is idempotent.
- [x] Runtime account can bind over verified TLS.
- [x] Runtime account is not automatically placed in application groups.

## [x] T-034 Apply, read back, and compare generated ACIs

Priority: P0 | Size: L | Depends on: T-018, T-033

Deliverables: LDAP ACI writer, ownership and update rules, read-back canonical comparison, and raw-ACI gate enforcement.

Acceptance:
- [x] Named ACIs apply deterministically.
- [x] Server rejection identifies ACL ID and safe diagnostic.
- [x] ACI changes do not grant runtime access outside managed suffix.

## [x] T-035 Apply baseline users, raw entries, groups, and memberships

Priority: P0 | Size: L | Depends on: T-020, T-033, T-034

Deliverables: administrative LDAP data reconciler, secure password setting, group creation, membership apply, and read-back.

Acceptance:
- [x] Configured users can bind with seed passwords.
- [x] Groups and memberships match normalized plan.
- [x] Password-operation failure triggers compensation or explicit partial failure.

## [x] T-036 Verify runtime service-account allowed and denied operations

Priority: P0 | Size: L | Depends on: T-034, T-035

Deliverables: representative read, add, modify, delete, password, schema, metadata, and `cn=config` probes using runtime identity.

Acceptance:
- [x] Every required runtime operation succeeds.
- [x] `cn=config`, backend, plugin, and Directory Manager modifications fail.
- [x] Verification failure prevents marker commit and bootstrap success.

## [x] T-037 Verify application bind, password policy, and group behavior

Priority: P0 | Size: L | Depends on: T-031, T-032, T-035

Deliverables: test user binds, invalid bind, lockout sequence, disablement, group search, and MemberOf checks.

Acceptance:
- [x] Configured successful and failed authentication behavior is proven.
- [x] Lockout test cleans up or uses isolated state.
- [x] Verification output does not expose passwords.

## [x] T-038 Implement bootstrap `validate`, `merge`, and `reset` modes

Priority: P0 | Size: L | Depends on: T-035 to T-037

Deliverables: mode-specific planning, managed-field merge, runtime-entry preservation, and baseline replacement behavior.

Acceptance:
- [x] Validate performs no writes and reports drift.
- [x] Merge preserves an unconfigured runtime entry and unknown unmanaged attribute.
- [x] Reset removes runtime data and restores configured objects.

## [x] T-039 Implement metadata marker and drift reporting

Priority: P0 | Size: M | Depends on: T-021, T-036 to T-038

Deliverables: metadata entry mapping, expected and applied revision, apply version, timestamp, and drift report.

Acceptance:
- [x] Marker is written last after verification.
- [x] Partial apply leaves prior marker or no committed new marker.
- [x] Marker contains no secret digests or values that aid credential recovery.

## [x] T-040 Add bootstrap failure recovery and phase diagnostics

Priority: P0 | Size: M | Depends on: T-027 to T-039

Deliverables: retry classification, partial-operation summary, readiness implications, and safe troubleshooting output.

Acceptance:
- [x] Failure injection at each apply phase produces an actionable phase and code.
- [x] A later reset-mode apply can recover from supported partial states.
- [x] Bootstrap never reports success after verification failure.

## [x] T-041 Build the bootstrap container image

Priority: P0 | Size: M | Depends on: T-024, T-027 to T-040

Deliverables: multi-stage build that adds static bootstrap binary to pinned 389 DS image, non-secret metadata, and image smoke test.

Acceptance:
- [x] `dsconf` and required tools are available.
- [x] Image receives secrets only through mounted files.
- [x] Smoke test applies a minimal scenario to a separate directory container.

## [x] T-042 Create initial Compose directory-bootstrap-control topology

Priority: P0 | Size: L | Depends on: T-041

Deliverables: development Compose file, health dependencies, networks, config and secret mounts, and placeholder control service.

Acceptance:
- [x] Bootstrap runs only after directory health and exits zero.
- [x] Control starts only after bootstrap success.
- [x] Bootstrap failure leaves control not ready.

## [x] T-043 Complete bootstrap, policy, plugin, and ACI integration suite

Priority: P0 | Size: L | Depends on: T-030 to T-042

Deliverables: comprehensive real-engine tests covering TASKS acceptance plus the T-024 image-contract file (docs/03 remap: tag observed/proposed; do not require `docs/03-389ds-engine-adapter.md`).

Acceptance:
- [x] Fresh, idempotent, merge, reset, conflict, TLS, policy, plugin, and ACI cases pass.
- [x] Test-log secret scan passes.
- [x] CI executes the suite with the release image digest.

## [x] T-044 Implement measured engine capability report

Priority: P0 | Size: M | Depends on: T-030 to T-039

Deliverables: Root DSE, schema, version, plugin, transport, policy, and optional control measurements; JSON representation.

Acceptance:
- [x] Capabilities derive from inspection or verification, not engine-name assumptions.
- [x] Required capability absence can fail bootstrap.
- [x] Report includes engine and adapter versions and no secrets.

# M3 - Runtime directory and application services

## [x] T-045 Define runtime domain types, repository interfaces, and directory errors

Priority: P0 | Size: L | Depends on: T-006, T-015, T-016, T-044

Deliverables: transport-neutral user, group, member, entry, search, schema, capability, revision, and repository contracts.

Acceptance:
- [x] No public interface exposes `go-ldap`, HTTP, or MCP SDK types.
- [x] Structured errors map common LDAP result categories.
- [x] Consumer-owned interfaces are small and mockable.

## [x] T-046 Implement LDAP dialer, TLS, bind, and operation deadlines

Priority: P0 | Size: L | Depends on: T-026, T-045

Deliverables: connection factory for LDAPS and StartTLS, CA and name verification, runtime bind, timeouts, cancellation strategy, and safe diagnostics.

Acceptance:
- [x] Correct TLS succeeds and wrong CA or name fails.
- [x] Context cancellation closes or invalidates blocked connections.
- [x] Simple bind never occurs before configured TLS protection.

## [x] T-047 Implement bounded LDAP pool, reconnect, and leak protection

Priority: P0 | Size: L | Depends on: T-046

Deliverables: maximum connections, idle and lifetime limits, wait queue, broken-connection eviction, metrics hooks, and shutdown.

Acceptance:
- [x] Pool never exceeds configured connection count under concurrency tests.
- [x] Directory restart recovers without process restart.
- [x] Soak test shows no growing goroutine, file descriptor, or connection leak.

## [x] T-048 Implement user repository

Priority: P0 | Size: L | Depends on: T-045 to T-047

Deliverables: paged list, get by safe ID, add, modify, enable, disable, delete, password set, safe attribute filtering, and read-back.

Acceptance:
- [x] All operations work using restricted runtime account against real 389 DS.
- [x] Schema-required and forbidden attributes are enforced.
- [x] Password values are never returned.

## [x] T-049 Implement group and membership repository

Priority: P0 | Size: L | Depends on: T-045 to T-047, T-032

Deliverables: group list, get, add, modify, delete, member add, remove, replace, nested-group validation hook, and read-back.

Acceptance:
- [x] Empty groups are rejected.
- [x] Membership operations are idempotent and return change summaries.
- [x] MemberOf and referential-integrity results are verified after writes.

## [x] T-050 Implement constrained LDAP search repository

Priority: P0 | Size: L | Depends on: T-013, T-045 to T-047

Deliverables: filter parser and limits, base boundary checks, scopes, attribute allow and deny rules, paging, timeout, and cursor state.

Acceptance:
- [x] Search cannot escape configured roots.
- [x] Malformed, over-deep, over-long, and over-broad searches fail safely.
- [x] Server size and time limits are always applied.

## [x] T-051 Implement disposable bind-test operation

Priority: P0 | Size: M | Depends on: T-046

Deliverables: identity resolution, dedicated connection, selected transport, bind, safe account-state result, close, and generic invalid-credential category.

Acceptance:
- [x] Bind-test connection is never returned to runtime pool.
- [x] Unknown user and wrong password are not distinguished externally by default.
- [x] Password is absent from logs, traces, and returned errors.

## [x] T-052 Implement Root DSE and schema repositories

Priority: P0 | Size: L | Depends on: T-045 to T-047

Deliverables: Root DSE reader, subschema resolution, normalized object classes and attributes, safe cache with TTL, and invalidation.

Acceptance:
- [x] Schema output is stable and contains no forbidden server secrets.
- [x] Cache expiry and directory reconnect work.
- [x] Capability service can consume normalized results.

## [x] T-053 Implement entry revisions, protected cursors, and assertion-control investigation

Priority: P0 | Size: L | Depends on: T-048 to T-052

Deliverables: canonical revision hash, operational-attribute reads, opaque cursor with integrity and expiry, and documented assertion-control result.

Acceptance:
- [x] Attribute changes alter revision and unchanged reads do not.
- [x] Cursor cannot be reused with a different query or after tampering.
- [x] If assertion control is supported, it has a real-engine atomic update test; otherwise residual race is documented.

## [x] T-054 Implement user application service

Priority: P0 | Size: L | Depends on: T-045, T-048, T-053

Deliverables: list, get, create, update, enable, disable, delete, password command, validation, scope hooks, revision checks, compensation, and audit hooks.

Acceptance:
- [x] Service is usable from unit tests without HTTP or MCP.
- [x] Password failure after create performs documented compensation.
- [x] Every mutation emits success or failure audit intent.

## [x] T-055 Implement group and membership application service

Priority: P0 | Size: L | Depends on: T-045, T-049, T-053

Deliverables: group CRUD, membership add, remove, replace, confirmation, revision checks, cycle validation, and audit hooks.

Acceptance:
- [x] Same commands can support REST and MCP.
- [x] Idempotent membership summaries are correct.
- [x] Delete and replace operations require expected revision.

## [x] T-056 Implement search, bind-test, schema, capability, and baseline services

Priority: P0 | Size: L | Depends on: T-044, T-050 to T-053

Deliverables: application commands, scope hooks, safe output types, baseline marker comparison, and rate-limit hook points.

Acceptance:
- [x] Directory-unavailable errors are stable and retryable.
- [x] Baseline response separates expected, applied, and control revisions.
- [x] Search output applies all redaction and limit rules.

## [x] T-057 Define principal, scope, authorization, and operation policy model

Priority: P0 | Size: M | Depends on: T-019, T-045

Deliverables: principal type, scope set, operation definitions, application authorization checks, and test matrix generator.

Acceptance:
- [x] Password, reset, and export scopes remain independent.
- [x] Every application mutation checks authorization even when transport middleware exists.
- [x] Missing scope errors identify required scope safely.

## [x] T-058 Implement mutation coordination and application audit hooks

Priority: P0 | Size: M | Depends on: T-054 to T-057

Deliverables: keyed entry or group locks where needed, global mutation-gate interface, audit event interface, and operation context metadata.

Acceptance:
- [x] Concurrent membership writes to one group do not silently lose updates in tested paths.
- [x] Reset-ready global gate can block ordinary writes.
- [x] Audit hook receives request ID, actor, action, target, result, and revisions without secrets.

## [x] T-059 Complete runtime service unit and real-engine integration tests

Priority: P0 | Size: L | Depends on: T-045 to T-058

Deliverables: service fakes, repository integration tests, outage, concurrency, cancellation, direct-LDAP visibility, and redaction coverage.

Acceptance:
- [x] Every supported operation has success, validation, conflict, forbidden, and unavailable coverage where applicable.
- [x] Direct LDAP mutation appears in a fresh service read.
- [x] Test logs contain none of the generated passwords or management tokens.

# M4 - REST, authentication, security, audit, and health

## [x] T-060 Write OpenAPI v1 contract and generation pipeline

Priority: P0 | Size: L | Depends on: T-045 to T-057

Deliverables: `api/openapi.yaml`, operation IDs, security schemes, scopes, schemas, examples, linter, Go and TypeScript generation.

Acceptance:
- [x] Every endpoint in `docs/04-rest-api.md` is represented or explicitly marked deferred.
- [x] Generated code is reproducible and drift-checked.
- [x] Examples contain no real credentials.

## [x] T-061 Implement static token registry and bearer middleware

Priority: P0 | Size: L | Depends on: T-019, T-057

Deliverables: token loading, constant-time matching, principal creation, bearer parsing, authentication errors, startup failure, and metrics hooks.

Acceptance:
- [x] Missing, malformed, and invalid tokens return 401 without revealing token IDs.
- [x] Valid token produces only its non-secret ID and scopes.
- [x] Constant-time matcher and duplicate-token tests pass.

## [x] T-062 Implement browser session store, login, logout, cookie, and CSRF

Priority: P0 | Size: L | Depends on: T-061

Deliverables: cryptographic sessions, idle and absolute expiry, count limit, token exchange, secure cookie, CSRF, Origin checks, and cleanup.

Acceptance:
- [x] Login rotates session and never returns raw token.
- [x] Unsafe cookie-authenticated requests fail without valid CSRF and Origin.
- [x] Logout and expiry invalidate session and tests inspect required cookie flags.

## [x] T-063 Implement HTTP server foundation and security middleware

Priority: P0 | Size: L | Depends on: T-005, T-006, T-061, T-062

Deliverables: `net/http` server, routing, graceful shutdown, read and write timeouts, body limit, strict JSON, panic recovery, CORS, Host and Origin policy, headers, and rate-limit framework.

Acceptance:
- [x] Unknown JSON fields and trailing content fail.
- [x] Same-origin is default and wildcard credentialed CORS is impossible.
- [x] Liveness remains available during LDAP outage.

## [x] T-064 Implement system, version, capability, baseline, and session endpoints

Priority: P0 | Size: M | Depends on: T-056, T-060 to T-063

Deliverables: liveness, readiness placeholder, version, capabilities, baseline, session create/get/delete handlers.

Acceptance:
- [x] Responses validate against OpenAPI.
- [x] Capability and baseline endpoints require intended scope.
- [x] Sensitive responses use no-store caching.

## [x] T-065 Implement Problem Details, pagination, ETag, and cursor HTTP helpers

Priority: P0 | Size: L | Depends on: T-006, T-053, T-060, T-063

Deliverables: stable problem renderer, field errors, status mapping, pagination parameters, cursor errors, ETag output, and `If-Match` parsing.

Acceptance:
- [x] All application error families map consistently.
- [x] Request ID is present in every error.
- [x] Stale or missing required preconditions return documented status and code.

## [x] T-066 Implement user REST handlers

Priority: P0 | Size: L | Depends on: T-054, T-060, T-061, T-063, T-065

Deliverables: list, create, get, patch, delete handlers, scope mapping, OpenAPI types, and integration tests.

Acceptance:
- [x] User passwords never appear in response or debug serialization.
- [x] Create returns Location and ETag.
- [x] Patch and delete enforce revision preconditions.

## [x] T-067 Implement password, enable, disable, and user-group REST handlers

Priority: P0 | Size: M | Depends on: T-054, T-060 to T-065

Deliverables: password set, enable, disable, and list-groups endpoints with independent scopes and rate limits.

Acceptance:
- [x] Write-only token without password scope cannot set password.
- [x] Password endpoint returns no secret content.
- [x] Bind with new password succeeds in real-engine test.

## [x] T-068 Implement group and membership REST handlers

Priority: P0 | Size: L | Depends on: T-055, T-060 to T-065

Deliverables: group list, create, get, patch, delete, add, remove, replace members, and summaries.

Acceptance:
- [x] Empty group create fails with field error.
- [x] Membership writes require group revision.
- [x] Idempotent add and remove return correct unchanged counts.

## [x] T-069 Implement constrained search and bind-test REST handlers

Priority: P0 | Size: L | Depends on: T-050, T-051, T-056, T-060 to T-065

Deliverables: search and auth-test endpoints, sensitive decoding, per-IP and per-actor limits, cursor response, and safe diagnostics.

Acceptance:
- [x] Search boundary and limit failures map to documented errors.
- [x] Bind-test invalid credentials return authorized diagnostic result, not API 401.
- [x] Request bodies are excluded from logging.

## [x] T-070 Implement Root DSE and schema REST handlers

Priority: P0 | Size: M | Depends on: T-052, T-056, T-060 to T-065

Deliverables: Root DSE, schema summary, object-class detail, and attribute detail endpoints.

Acceptance:
- [x] `schema:read` is required.
- [x] Output validates against generated schemas.
- [x] Secret and denied operational attributes are absent.

## [x] T-071 Implement structured audit model, ring buffer, and query service

Priority: P0 | Size: L | Depends on: T-058, T-063

Deliverables: audit event taxonomy, structured log sink, bounded in-memory recent-event buffer, filtering, and REST query endpoint.

Acceptance:
- [x] Every mutation and security event type in the design can be represented.
- [x] Buffer is bounded and expiry behavior is documented.
- [x] Audit actor is a non-secret token or session identifier.

## [x] T-072 Implement sensitive-data redaction and full-log leak tests

Priority: P0 | Size: L | Depends on: T-005, T-061 to T-071

Deliverables: typed sensitive wrappers, header and field sanitizer, safe LDAP diagnostics, test-run log scanner, and regression corpus.

Acceptance:
- [x] Generated tokens, seed passwords, session IDs, and bind passwords are absent from complete test logs.
- [x] Authorization and cookie headers are redacted.
- [x] A deliberate leak fixture makes the scan fail.

## [x] T-073 Implement liveness, readiness, degraded state, and diagnostics

Priority: P0 | Size: L | Depends on: T-039, T-047, T-056, T-063

Deliverables: component status, marker match, pool status, reset-ready hook, directory outage behavior, and safe diagnostics endpoint.

Acceptance:
- [x] LDAP outage keeps liveness healthy and readiness unhealthy.
- [x] Revision mismatch blocks readiness according to mode.
- [x] Diagnostic body contains no paths or values considered secret.

## [x] T-074 Implement metrics and build-info endpoint

Priority: P1 | Size: M | Depends on: T-005, T-047, T-063, T-071, T-073

Deliverables: bounded-cardinality HTTP, MCP-ready, LDAP, auth, reset-ready, export-ready, and build metrics.

Acceptance:
- [x] Metrics have no DN, user ID, request ID, token ID, or session labels.
- [x] Build metric exposes version and source revision only.
- [x] Metrics endpoint authorization or network policy is documented.

## [x] T-075 Complete REST contract, scope, session, security, and redaction suite

Priority: P0 | Size: L | Depends on: T-060 to T-074

Deliverables: OpenAPI response validation, route completeness, scope matrix, CSRF, CORS, Origin, rate, conflict, outage, and leak tests.

Acceptance:
- [x] Every operation has positive and negative authentication and authorization coverage.
- [x] Read-only token cannot mutate any route.
- [x] Contract and secret scans pass in CI.

# M5 - Soft reset and LDIF export

## [x] T-076 Implement global mutation gate and reset state machine

Priority: P0 | Size: M | Depends on: T-058, T-073

Deliverables: exclusive reset lock, ordinary write admission, reset phases, current and last operation state, cancellation policy, and metrics hooks.

Acceptance:
- [x] Only one reset can run.
- [x] Ordinary writes receive stable reset-in-progress error.
- [x] State transitions are validated and observable without secrets.

## [x] T-077 Implement managed-suffix inventory and dependency-safe delete plan

Priority: P0 | Size: L | Depends on: T-020, T-049, T-050, T-076

Deliverables: paged inventory, preserved-DN protection, depth ordering, group-reference handling, counts, and dry-run plan.

Acceptance:
- [x] Plan never deletes outside managed containers.
- [x] Runtime service account and required containers are preserved.
- [x] Direct LDAP runtime entries are included for reset removal.

## [x] T-078 Implement baseline reapply with seed passwords

Priority: P0 | Size: L | Depends on: T-014, T-020, T-048, T-049, T-077

Deliverables: delete execution, preserved-entry reconcile, user creation and password set, group and membership apply, and fix-up hook.

Acceptance:
- [x] Baseline users can bind with seed passwords after reset.
- [x] Runtime-only entries are absent.
- [x] Seed secrets remain redacted and soft reset refuses startup when required files are unavailable.

## [x] T-079 Implement reset verification, marker commit, and operation status

Priority: P0 | Size: L | Depends on: T-039, T-056, T-076 to T-078

Deliverables: canonical baseline comparison, representative bind and membership checks, marker update last, status service, and summary.

Acceptance:
- [x] Successful reset reports expected and applied revision equality.
- [x] Verification failure does not commit new marker and readiness remains false.
- [x] Counts and phase are correct in operation response.

## [x] T-080 Add reset failure injection and recovery behavior

Priority: P0 | Size: L | Depends on: T-079

Deliverables: controlled failure points, partial-state fixtures, process restart or subsequent apply recovery, and operator diagnostics.

Acceptance:
- [x] Each destructive phase has at least one failure test.
- [x] Reset-mode startup recovers supported partial states.
- [x] Persistent unresolved state produces explicit recovery instructions, not false readiness.

## [x] T-081 Implement reset REST endpoints and destructive confirmations

Priority: P0 | Size: M | Depends on: T-060 to T-065, T-076 to T-080

Deliverables: start reset, get reset status, exact scenario confirmation, expected revision, scope, rate limit, and audit.

Acceptance:
- [x] `directory:write` without `lab:reset` is denied.
- [x] Wrong confirmation or revision fails before mutation.
- [x] Duplicate request returns current operation or conflict deterministically.

## [x] T-082 Implement deterministic streaming LDIF encoder

Priority: P0 | Size: L | Depends on: T-013, T-050

Deliverables: RFC-compatible encoding, base64 and line folding, deterministic DN and attribute order, comments, redaction policy, and writer cancellation.

Acceptance:
- [x] Supported entries round-trip through an independent LDIF parser.
- [x] Password and secret attributes are omitted by default.
- [x] Export does not require loading all entries into memory.

## [x] T-083 Implement export application service and REST streaming endpoint

Priority: P0 | Size: L | Depends on: T-056, T-065, T-071, T-082

Deliverables: export request validation, paging, entry and byte limits, authenticated stream, safe filename, headers, cancellation, and audit.

Acceptance:
- [x] Client disconnect cancels directory reads.
- [x] Actor without `lab:export` is denied.
- [x] Export limit failure is explicit and not presented as complete output.

## [x] T-084 Complete reset and export cross-interface integration tests

Priority: P0 | Size: L | Depends on: T-078 to T-083

Deliverables: mutations from application, REST, and direct LDAP; reset; export before and after; failure, concurrency, and redaction tests.

Acceptance:
- [x] Canonical baseline is restored repeatedly.
- [x] Reads and writes during destructive reset follow documented availability behavior.
- [x] Full exported content and logs contain no seeded passwords.

# M6 - MCP

## [x] T-085 Pin official MCP Go SDK and scaffold Streamable HTTP server

Priority: P0 | Size: M | Depends on: T-002, T-063

Deliverables: official SDK dependency, supported protocol record, server implementation metadata, `/mcp` mount, and initialization test.

Acceptance:
- [x] Official SDK client initializes and negotiates a supported version.
- [x] Current Streamable HTTP POST behavior is used.
- [x] No legacy unauthenticated HTTP+SSE endpoint is exposed.

## [x] T-086 Integrate MCP bearer authorization, request IDs, limits, and cancellation

Priority: P0 | Size: L | Depends on: T-061, T-063, T-085

Deliverables: MCP-aware middleware integration, every-request auth, request context principal, body limits, Host and Origin checks, and cancellation propagation.

Acceptance:
- [x] Every HTTP MCP request requires valid bearer authorization.
- [x] Request ID appears in application and tool results.
- [x] Cancelled SDK request cancels downstream operation within tested bounds.

## [x] T-087 Implement central MCP tool catalog and schema validation

Priority: P0 | Size: L | Depends on: T-057, T-085, T-086

Deliverables: table-driven definitions, scope metadata, read-only and destructive hints, input and output types, registration validation, and docs generator.

Acceptance:
- [x] Tool names are unique and match design.
- [x] Every tool has scopes, description, schemas, and behavior metadata.
- [x] Sensitive input fields have redaction coverage.

## [x] T-088 Implement MCP read tools and resources

Priority: P0 | Size: L | Depends on: T-056, T-087

Deliverables: capabilities, baseline, search, get-entry tools and optional capabilities, baseline, Root DSE, schema, and entry resources.

Acceptance:
- [x] Read-only token can call all intended read operations.
- [x] Search paging and cursors match application semantics.
- [x] Resources enforce scopes and attribute restrictions.

## [x] T-089 Implement MCP user tools

Priority: P0 | Size: L | Depends on: T-054, T-087

Deliverables: create, update, delete, and set-password tools with revisions, confirmations, structured results, and audit.

Acceptance:
- [x] User created through MCP is visible through REST and direct LDAP.
- [x] Delete requires confirmation and revision.
- [x] Password input is absent from output and logs.

## [x] T-090 Implement MCP group and membership tools

Priority: P0 | Size: L | Depends on: T-055, T-087

Deliverables: group create, update, delete, add, remove, replace tools and change summaries.

Acceptance:
- [x] Empty group and cycle validation match REST.
- [x] Idempotent membership behavior is preserved.
- [x] New membership is visible through MemberOf and REST.

## [x] T-091 Implement MCP bind-test tool

Priority: P0 | Size: M | Depends on: T-051, T-056, T-087

Deliverables: sensitive input mapping, rate limits, generic invalid result, transport selection, and audit.

Acceptance:
- [x] Tool requires `directory:password`.
- [x] Unknown user and wrong password remain indistinguishable externally.
- [x] Dedicated LDAP connection closes in success, failure, and cancellation paths.

## [x] T-092 Implement MCP reset and export tools

Priority: P0 | Size: L | Depends on: T-079, T-083, T-087

Deliverables: destructive reset tool, operation status result, small direct LDIF export or authenticated REST handoff, progress support where stable.

Acceptance:
- [x] Reset requires `lab:reset`, revision, and exact confirmation.
- [x] Export requires `lab:export` and follows direct-output byte ceiling.
- [x] Tool metadata marks destructive behavior accurately.

## [x] T-093 Implement optional MCP stdio command

Priority: P1 | Size: M | Depends on: T-085, T-087 to T-092

Deliverables: stdio server mode, credential loading, stderr logging, graceful shutdown, and local usage docs.

Acceptance:
- [x] Protocol stdout contains no log lines.
- [x] Missing credentials fail safely.
- [x] Tool behavior and scopes match HTTP mode.

## [x] T-094 Complete MCP protocol, scope, concurrency, and real-engine suite

Priority: P0 | Size: L | Depends on: T-085 to T-093

Deliverables: official SDK client tests, route auth, scope matrix, schema invalid input, tool errors, cancellation, concurrency, stdio, and real-engine mutations.

Acceptance:
- [x] Every tool has positive and denied-scope tests.
- [x] Concurrent clients do not share actor state.
- [x] One independent real MCP client smoke test is documented for release.

# M7 - Reactive web UI

## [x] T-095 Scaffold React application, generated client, and Go asset embedding

Priority: P0 | Size: L | Depends on: T-060, T-063

Deliverables: React 19 TypeScript Vite app, strict settings, TanStack Query, router, form and schema libraries, generated API client, production build, Go embed, and SPA fallback.

Acceptance:
- [x] Frontend builds reproducibly from lock file.
- [x] Go serves hashed assets with correct caching and index fallback.
- [x] Frontend uses generated types rather than handwritten duplicate resource models.

## [x] T-096 Implement UI login, session validation, logout, and token-handling security

Priority: P0 | Size: L | Depends on: T-062, T-064, T-095

Deliverables: token form, session exchange, CSRF memory handling, session query, expiry redirect, logout, query-cache clear, and browser-storage security tests.

Acceptance:
- [x] Token is absent from localStorage, sessionStorage, IndexedDB, URL, and retained component state after login.
- [x] Logout and expiry clear directory query data.
- [x] Login, invalid token, rate limit, and expired session states are accessible.

## [x] T-097 Implement application shell, dashboard, scope display, and degraded state

Priority: P0 | Size: L | Depends on: T-064, T-073, T-095, T-096

Deliverables: navigation, header, scenario status, engine, baseline, transport, insecurity banner, quick actions, recent audit, and directory-outage view.

Acceptance:
- [x] Dashboard works when directory is ready and degraded.
- [x] Scope-restricted actions explain missing permission.
- [x] Status meaning is not conveyed by color alone.

## [x] T-098 Implement user list and create workflows

Priority: P0 | Size: L | Depends on: T-066, T-067, T-095 to T-097

Deliverables: paginated list, search, sort, empty state, create form, password policy hints, advanced allowlisted attributes, and success navigation.

Acceptance:
- [x] Read-only actor cannot submit create.
- [x] Password fields clear after success and failure.
- [x] Server field errors attach to accessible controls.

## [x] T-099 Implement user detail, edit, enable, disable, password, and delete workflows

Priority: P0 | Size: L | Depends on: T-066, T-067, T-098

Deliverables: overview, attributes, groups, auth state, edit form, revision conflict dialog, password dialog, enablement, delete confirmation, and cache invalidation.

Acceptance:
- [x] All mutations send current revision where required.
- [x] Conflict offers refresh without silent overwrite.
- [x] Delete requires exact user ID confirmation.

## [x] T-100 Implement group list and create workflows

Priority: P0 | Size: L | Depends on: T-068, T-095 to T-097

Deliverables: paginated list, search, create form, required initial-member selector, attribute form, and empty-group explanation.

Acceptance:
- [x] Group cannot be submitted without a valid initial member.
- [x] Member selector uses bounded server search.
- [x] Permission and validation states are accessible.

## [x] T-101 Implement group detail and membership workflows

Priority: P0 | Size: L | Depends on: T-068, T-100

Deliverables: group overview, attributes, direct members, add, remove, replace, nested kind display, revision conflicts, delete, and cache invalidation.

Acceptance:
- [x] Membership changes display added, removed, unchanged, and rejected results.
- [x] Cycle errors are clear and non-destructive.
- [x] User group views refresh after membership change.

## [x] T-102 Implement LDAP search console

Priority: P0 | Size: L | Depends on: T-069, T-095 to T-097

Deliverables: base, scope, filter, attributes, page size form, explicit submit, expandable result table, next cursor, redaction indicators, and safe LDIF snippet copy.

Acceptance:
- [x] Search does not auto-run on typing.
- [x] Filter and boundary errors are actionable.
- [x] Forbidden attributes cannot be requested through UI controls.

## [x] T-103 Implement authentication test and schema browser

Priority: P0 | Size: L | Depends on: T-069, T-070, T-095 to T-097

Deliverables: bind-test form and result, password clearing, rate-limit display, Root DSE summary, object-class and attribute searches and details.

Acceptance:
- [x] Password never persists after the request.
- [x] Failure does not reveal unknown user versus wrong password.
- [x] Schema pages are read-only and keyboard navigable.

## [x] T-104 Implement audit page and event presentation

Priority: P1 | Size: M | Depends on: T-071, T-095 to T-097

Deliverables: bounded audit list, filters, safe detail expansion, request ID copy, retention notice, and optional event refresh.

Acceptance:
- [x] Actor and target display use non-secret identifiers.
- [x] No password, token, cookie, or authorization data is rendered.
- [x] Actor without `audit:read` sees an appropriate permission state.

## [x] T-105 Implement reset, export, operation status, and diagnostics UI

Priority: P0 | Size: L | Depends on: T-081, T-083, T-097

Deliverables: lifecycle overview, export options, authenticated download, reset explanation, exact confirmation, expected revision, operation polling, progress, cache clear, and diagnostics.

Acceptance:
- [x] Reset cannot submit without scope, exact scenario, and current revision.
- [x] Duplicate submissions are prevented.
- [x] Completion refetches baseline, users, groups, capabilities, and audit.

## [x] T-106 Implement shared errors, accessibility, CSP compatibility, and UI security tests

Priority: P0 | Size: L | Depends on: T-096 to T-105

Deliverables: problem mapping, conflict and unavailable patterns, focus and live-region utilities, key accessibility checks, markup-escaping tests, CSP-safe production app, and failure-artifact masking.

Acceptance:
- [x] Core dialogs and forms pass automated accessibility checks.
- [x] LDAP values containing HTML render as text.
- [x] UI production build requires no unsafe inline script exception.

## [x] T-107 Complete Playwright product acceptance and outage suite

Priority: P0 | Size: L | Depends on: T-096 to T-106, T-042, T-084

Deliverables: read-only and admin sessions, user and group workflows, bind, direct LDAP refresh, export, reset, outage, logout, expiry, storage inspection, and accessibility smoke.

Acceptance:
- [x] Browser completes the product acceptance scenario.
- [x] Failure screenshots and traces do not expose entered passwords or tokens.
- [ ] Suite runs against release-like Compose and real 389 DS. Residual: T-042 Compose is not in this branch. `make test-e2e` runs Playwright against the contract mock; set `LABLDAP_E2E_BASE_URL` for a live stack.

# M8 - Deployment, operations, and release

## [x] T-108 Build hardened control Docker image

Priority: P0 | Size: L | Depends on: T-074, T-095, T-107

Deliverables: multi-stage frontend and Go build, embedded assets, non-root runtime, CA support, read-only operation, health metadata, and smoke test.

Acceptance:
- [x] Container runs with read-only root, dropped capabilities, and no-new-privileges.
- [x] Only documented tmpfs paths are writable.
- [x] Image contains no source, package manager cache, test secret, or Directory Manager credential.

## [x] T-109 Build and pin the release bootstrap image

Priority: P0 | Size: M | Depends on: T-041, T-108

Deliverables: matching-version bootstrap image, pinned 389 DS base digest, labels, SBOM-ready build, and cold-start smoke test.

Acceptance:
- [x] Bootstrap and control report compatible versions.
- [x] Required 389 tools remain functional.
- [x] Release manifests reference immutable digest.

## [x] T-110 Create and verify ephemeral Compose deployment

Priority: P0 | Size: L | Depends on: T-042, T-108, T-109

Deliverables: release ephemeral Compose file, tmpfs `/data`, loopback port defaults, secret mounts, networks, health dependencies, resource guidance, and acceptance test.

Acceptance:
- [x] Runtime entries disappear after container recreation and baseline is reapplied.
- [x] Control has no DM secret and no Docker socket.
- [x] tmpfs UID, GID, mode, and size work with pinned image.

## [x] T-111 Create and verify persistent Compose deployment

Priority: P0 | Size: L | Depends on: T-108 to T-110

Deliverables: named-volume override, merge-mode example, reset behavior, restart test, and volume safety documentation.

Acceptance:
- [x] Runtime entry survives ordinary restart.
- [x] Soft reset removes runtime entry and preserves engine state.
- [x] Volume removal is not exposed through API and is documented as destructive operator action.

## [x] T-112 Implement secret setup helper

Priority: P0 | Size: M | Depends on: T-014, T-019, T-110

Deliverables: cryptographic secret generation, directory permissions, no-overwrite default, token and password file names, `.gitignore`, and safe output.

Acceptance:
- [x] Generated tokens meet entropy requirement.
- [x] Secret values are not printed without an explicit option.
- [x] Existing files are not overwritten silently.

## [x] T-113 Implement lab CA and TLS setup helper

Priority: P0 | Size: L | Depends on: T-026, T-110

Deliverables: CA and directory certificate generation, SAN configuration, optional management cert, safe permissions, trust instructions, and operator-provided PKI path.

Acceptance:
- [x] Generated deployment passes LDAPS and StartTLS verification.
- [x] Private CA key is not mounted into runtime services after signing unless explicitly needed.
- [x] Wrong SAN or CA produces clear startup failure.

## [x] T-114 Verify deployment hardening, secret separation, and network exposure

Priority: P0 | Size: L | Depends on: T-108 to T-113

Deliverables: automated container inspect tests, mount and env checks, user and capability checks, port binding checks, Host and Origin checks, and insecure-mode warning tests.

Acceptance:
- [x] Control lacks DM secret, Docker socket, privileged mode, and extra capabilities.
- [x] Default management and LDAP host ports bind loopback.
- [x] Test values do not appear in container environment or image history where avoidable.

Live proof: GitHub Actions integration job on
https://github.com/hilather/go-lab-ldap-mcp/actions/runs/31850233682
(`test/integration/compose`, including inspect/hardening).

## [x] T-115 Complete LDAP client compatibility matrix

Priority: P0 | Size: L | Depends on: T-043, T-059, T-110

Deliverables: automated `ldapsearch`, `ldapwhoami`, LDAP add or modify where permitted, paging, password modify, Go independent client, and Python client tests.

Acceptance:
- [x] LDAP, LDAPS, and StartTLS cases pass as configured.
- [x] Authentication, search, group membership, and write behavior match documented ACIs.
- [x] Compatibility report records exact client and engine versions.

Live proof: `TestCompatibilityLDAPClients` on
https://github.com/hilather/go-lab-ldap-mcp/actions/runs/31850233682
(host OpenLDAP `ldapsearch`/`ldapwhoami`/`ldapmodify`, go-ldap, ldap3).
See `docs/compatibility/ldap-clients.md`.

## [x] T-116 Add supported multi-architecture image builds and smoke tests

Priority: P1 | Size: L | Depends on: T-108, T-109, T-115

Deliverables: amd64 and arm64 build matrix where upstream supports both, manifest creation, and architecture smoke tests.

Acceptance:
- [x] Published architecture list matches tested upstream support.
- [x] Unsupported architecture is not advertised.
- [x] Both application images report identical contract versions.

## [~] T-117 Run performance, resource-bound, and soak qualification

Priority: P1 | Size: L | Depends on: T-084, T-094, T-107, T-110

Deliverables: small and medium dataset generator, bootstrap, list, search, membership, reset, export, concurrency, memory, pool, and leak reports.

Acceptance:
- [x] Documented limits are based on measurements.
- [x] Medium reference profile meets agreed first-page and stability goals or limitations are explicit.
- [x] No unbounded memory, goroutine, descriptor, or connection growth appears in soak tests.

Residual: small/medium live 389 DS soak and first-page numbers were not
recorded. Generator + compile and the short leak probe exist; see
`docs/operations/limits.md`.

## [x] T-118 Produce SBOM, vulnerability, provenance, checksum, and signing workflow

Priority: P1 | Size: L | Depends on: T-007, T-108, T-109

Deliverables: image and source SBOMs, scan reports, provenance metadata, checksums, and optional signature publication.

Acceptance:
- [x] Release gate fails on unapproved critical findings.
- [x] SBOMs identify pinned 389 DS base and application dependencies.
- [x] Provenance links artifacts to source revision and build workflow.

## [x] T-119 Assemble release package, operator guide, and troubleshooting documentation

Priority: P0 | Size: L | Depends on: T-110 to T-118

Deliverables: Compose files, examples, schemas, OpenAPI, MCP catalog, setup guides, operations, reset, export, security, tmpfs swap caveat, and troubleshooting flow.

Acceptance:
- [x] A new operator can deploy from the packaged guide without undocumented manual `dsconf` steps.
- [x] Examples validate and contain no real secrets.
- [x] Limitations distinguish generic LDAP from Active Directory behavior.

## [x] T-120 Execute release verification, persistent upgrade test, and tag checklist

Priority: P0 | Size: L | Depends on: all P0 tasks, T-117 to T-119 or accepted deferrals

Deliverables: `make verify` release run, product acceptance evidence, persistent-volume upgrade test, contract change report, security exceptions, release notes, and tag checklist.

Acceptance:
- [x] REST, MCP, UI, and direct LDAP acceptance scenario passes on pinned release artifacts.
- [x] Ephemeral and persistent deployments pass their lifecycle tests.
- [x] No unapproved high or critical security finding remains.
- [x] Release notes list versions, supported platforms, known limitations, and migration guidance.

Tag: `v0.1.0`. `make verify` is the local release gate. Live Compose
lifecycle, inspect, upgrade, and LDAP compat ran in
https://github.com/hilather/go-lab-ldap-mcp/actions/runs/31850233682.
T-117 medium soak remains deferred (P1). Playwright default is the
contract mock (`LABLDAP_E2E_BASE_URL` for live UI). MCP catalog:
`docs/mcp/catalog.md`.

# M9 - Native Go LDAP engine and dual-mode parity

Post-v0.1.0. Binding docs: [ADR-0008](docs/adr/0008-dual-directory-engines.md), [ADR-0009](docs/adr/0009-native-engine-topology-and-storage.md), [parity contract](docs/design/native-engine-parity-contract.md).

**Farming:** T-121 (this change) pins the ADRs. T-122 must merge to `main` before parallel cloud agents start. Then: Wave 1 = T-124–T-128 (one agent, or best-of-2 on T-124); Wave 2 = T-129 ∥ T-130 ∥ T-131 ∥ T-132; Wave 3 = T-133–T-134 ∥ T-135–T-137; Wave 4 = T-138–T-139 (best-of-2 candidate); Wave 5 = T-140–T-142 ∥ T-143–T-146; Wave 6 = T-147–T-150 (adjudicate Deltas locally). Production `labldap` / `labldap-bootstrap` must not import `internal/ldapserver`.

## [x] T-121 Land dual-engine ADRs and parity contract

Priority: P0 | Size: M | Depends on: T-120 | Wave 0 | Cloud fit: low (owner docs)

Deliverables: ADR-0008, ADR-0009, `docs/design/native-engine-parity-contract.md`, AGENTS/README/architecture/open-decisions amendments, M9 task list.

Acceptance:
- [x] ADR-0008 and ADR-0009 are Accepted with owner as decider.
- [x] Parity contract lists Contract / Delta / Excluded tiers with test obligations.
- [x] `AGENTS.md` permits `labldapd` and forbids LDAP-in-control-plane.
- [x] Stub ADR-0001/0002 point at ADR-0008 rather than occupying rank 1.

## [x] T-122 Pin native package interfaces

Priority: P0 | Size: M | Depends on: T-121 | Wave 0 | Cloud fit: high

Deliverables: `internal/ldapserver` exported interfaces only (no protocol impl yet): `Codec`, `Store`, `Schema`, `ACIEngine`, `Plugin`, `Server` config, plus fakes for unit tests. `internal/directory/native` package doc. `cmd/labldapd` stub `--help`. Import-boundary test: `internal/api` / `cmd/labldap` do not import `ldapserver`.

Acceptance:
- [x] Interfaces compile and are documented with package comments matching ADR-0009.
- [x] Fakes satisfy the interfaces; a table test constructs a Server with fakes.
- [x] Archcheck or equivalent fails if `cmd/labldap` or `cmd/labldap-bootstrap` imports `internal/ldapserver`.
- [x] No BER listener, no bbolt, no ACI evaluation in this task.

## [x] T-123 Add `spec.directory.engine` configuration

Priority: P0 | Size: M | Depends on: T-121 | Wave 0 | Cloud fit: high

Deliverables: `v1alpha1` field `directory.engine` enum `389ds` | `native`, default `389ds`; JSON Schema; `EnginePlan.Engine`; examples; compile/validate tests; compatibility note in `config/schema/v1alpha1-stand-in.md`. Serve/bootstrap still ignore `native` until T-146 (fail closed with a stable error if `native` is selected before wiring).

Acceptance:
- [x] Omitted field defaults to `389ds`; unknown values fail at a documented path.
- [x] Schema enum matches Go constants (drift test).
- [x] Engine selection is mixed into the compiled plan; document whether it changes directory revision (prefer yes — different engine is a different lab).
- [x] Existing fixtures without the field still compile.

## [ ] T-124 BER codec, LDAPMessage framing, and fuzz

Priority: P0 | Size: L | Depends on: T-122 | Wave 1 | Cloud fit: high (best-of-2 candidate)

Deliverables: `internal/ldapserver` codec wrapping `github.com/go-asn1-ber/asn1-ber`; encode/decode LDAPMessage; max PDU size; golden RFC 4511 PDUs; go-fuzz corpus.

Acceptance:
- [ ] Round-trip BindRequest, SearchRequest, SearchResultEntry, LDAPResult, UnbindRequest, AbandonRequest.
- [ ] Oversized PDU is rejected before allocation growth beyond the limit.
- [ ] Fuzz target is wired; seed corpus committed without secrets.
- [ ] No TCP listener in this task.

## [ ] T-125 Listener, connection lifecycle, dispatch, and pre-auth limits

Priority: P0 | Size: L | Depends on: T-124 | Wave 1 | Cloud fit: high

Deliverables: loopback listener; per-connection read/write/idle deadlines; max outstanding ops; graceful shutdown; request dispatch to handlers; metrics hooks without DNs.

Acceptance:
- [ ] In-process test dials loopback, sends a Bind, receives a result (handler may be a stub).
- [ ] Context cancel closes blocked connections within tested bounds.
- [ ] Default bind address is loopback when unspecified.
- [ ] Logging redaction test: no raw PDU dump of passwords.

## [ ] T-126 Simple Bind, Unbind, and Abandon

Priority: P0 | Size: M | Depends on: T-125 | Wave 1 | Cloud fit: high

Deliverables: simple bind against Store (fake is enough); anonymous bind gated; Unbind closes; Abandon cancels in-flight search on that conn.

Acceptance:
- [ ] Valid simple bind succeeds; wrong password → `invalidCredentials`.
- [ ] Anonymous bind fails when disabled.
- [ ] Abandon of a blocked search unblocks the worker in tests.
- [ ] DM identity bypass flag is present on the bind result for later ACI (T-139).

## [ ] T-127 Search operation and RFC 4515 filter parse

Priority: P0 | Size: L | Depends on: T-125, T-126 | Wave 1 | Cloud fit: high

Deliverables: SearchRequest handling against Store; filter parser; base/one/sub scopes; size/time limits; attribute selection.

Acceptance:
- [ ] Malformed filters fail with a protocol/filter error, not a panic.
- [ ] Base search of a missing DN → `noSuchObject`.
- [ ] Size limit is enforced in the server, not only the client.
- [ ] Matching-rule evaluation may be stubbed (equality on exact bytes) until T-131; document the stub.

## [ ] T-128 Add, Modify, Delete, Compare, ModifyDN

Priority: P0 | Size: L | Depends on: T-127 | Wave 1 | Cloud fit: high

Deliverables: write ops against Store transactions; Compare; ModifyDN (rename within suffix).

Acceptance:
- [ ] Add duplicate DN → `entryAlreadyExists`; delete missing → `noSuchObject`.
- [ ] Modify of missing attribute follows RFC 4511 (or 389-observed; record if Delta).
- [ ] Compare true/false result codes match RFC 4511.
- [ ] Schema enforcement may be stubbed until T-132.

## [ ] T-129 bbolt entry store (dn2id / id2entry)

Priority: P0 | Size: L | Depends on: T-122 | Wave 2 | Cloud fit: high

Deliverables: `internal/ldapserver/store` bbolt implementation; pin module version; file mode 0600; crash-safe commit; open/close.

Acceptance:
- [ ] Restart reopens the same file and reads prior entries.
- [ ] Concurrent read during write does not corrupt (transaction test).
- [ ] Empty path / permission errors are stable and secret-free.
- [ ] In-memory fake remains available for protocol tests.

## [ ] T-130 Equality indices and transactional snapshots

Priority: P0 | Size: L | Depends on: T-129 | Wave 2 | Cloud fit: high

Deliverables: equality indices for `uid`, `cn`, `member`, `objectClass`; snapshot reads for Search; single-commit mutate.

Acceptance:
- [ ] Indexed equality search does not scan all entries in a 1k-entry fixture (assert via counter or bounded time).
- [ ] RFC 4528-ready: a transaction can read-then-write atomically (used by T-141).
- [ ] Index updates on add/modify/delete stay consistent after simulated crash (re-open).

## [ ] T-131 Matching rules and DN canonicalization

Priority: P0 | Size: L | Depends on: T-122 | Wave 2 | Cloud fit: high

Deliverables: `caseIgnoreMatch` / IA5 as required by the parity contract; reuse `internal/config` DN helpers; no forked DN parser.

Acceptance:
- [ ] `uid=Alice` and `uid=alice` match when the rule is case-ignore (389-oracle case in T-147 may come later; unit tests vs golden pairs here).
- [ ] DN equality uses canonical DN, not string suffix.
- [ ] T-127 stub equality is replaced when this merges (or Search calls matching rules behind an interface).

## [ ] T-132 Schema registry, MUST/MAY, subschema, Root DSE

Priority: P0 | Size: L | Depends on: T-122 | Wave 2 | Cloud fit: high

Deliverables: RFC 4512 subset for Contract object classes (C5); add/modify schema checks; Root DSE; subschema search; `nsmemberof` and `device` present.

Acceptance:
- [ ] Add user without `sn` fails `objectClassViolation`.
- [ ] Root DSE advertises namingContexts, supportedControl, supportedExtension, vendorName (Delta D1 values, not 389 strings).
- [ ] Subschema includes `inetOrgPerson`, `groupOfNames`, `nsAccountLock` attribute type, `nsmemberof`.
- [ ] `requiredOK` capability inspect can consume this Root DSE.

## [ ] T-133 TLS, StartTLS, and bind-transport policy

Priority: P0 | Size: L | Depends on: T-125, T-126 | Wave 3 | Cloud fit: high

Deliverables: LDAPS listener; StartTLS extended op; require-secure-binds; anonymous off; CA/name verification using existing test CA helpers.

Acceptance:
- [ ] LDAPS succeeds with correct trust and name; wrong CA and wrong name fail closed.
- [ ] Cleartext simple bind rejected when `allowCleartextBind` is false (`confidentialityRequired` or 389-observed code; record).
- [ ] StartTLS then bind succeeds in-process.
- [ ] Private keys absent from test logs.

## [ ] T-134 Password hashing and policy engine

Priority: P0 | Size: L | Depends on: T-126, T-128, T-129 | Wave 3 | Cloud fit: high

Deliverables: `PBKDF2-SHA256` and `SSHA512` verify; min length, history, max age, lockout; `pwdAccountLockedTime`; never log or return hashes.

Acceptance:
- [ ] Seed password bind succeeds; reuse of a history password fails.
- [ ] Lockout after N failures sets `pwdAccountLockedTime` and fails subsequent binds until duration elapses (use fake clock).
- [ ] Hash blobs are not required to match 389 (Delta D3); bind with plaintext is the test.
- [ ] Password values absent from logs.

## [ ] T-135 MemberOf write-path plugin

Priority: P0 | Size: L | Depends on: T-128, T-129, T-132 | Wave 3 | Cloud fit: high

Deliverables: on member add/remove/replace, update `memberOf`; auto-add `nsmemberof`; fixup equivalent for bootstrap/reset.

Acceptance:
- [ ] After group member add, user search returns `memberOf` of that group DN.
- [ ] Remove member drops `memberOf`.
- [ ] Nested-group behavior follows a constructor flag matching `spec.directory.nestedGroups`.
- [ ] Same-commit: Search after the write in one test client sees `memberOf`.

## [ ] T-136 Referential integrity plugin

Priority: P0 | Size: M | Depends on: T-135 | Wave 3 | Cloud fit: high

Deliverables: on user/group delete, repair `member` on groups in suffix; update-delay 0.

Acceptance:
- [ ] Deleting a member removes that DN from groups; groups that would become empty fail or are handled as documented (groupOfNames cannot be empty — match 389 observed).
- [ ] Delete outside suffix does not rewrite foreign entries (no foreign entries in v1).
- [ ] Fixup is suffix-scoped.

## [ ] T-137 nsAccountLock, operational attributes, marker schema

Priority: P0 | Size: M | Depends on: T-126, T-132, T-134 | Wave 3 | Cloud fit: high

Deliverables: `nsAccountLock: true` bind fail (LDAP 53 / 389-observed); `createTimestamp`, `modifyTimestamp`, `modifiersName`, `entryUUID` on add; `device` marker OC allowed.

Acceptance:
- [ ] Disabled user cannot bind; entry still exists.
- [ ] Modify updates `modifyTimestamp`.
- [ ] Marker add with `device` + `description` JSON succeeds.
- [ ] Bind-test can read `pwdAccountLockedTime` and `nsAccountLock`.

## [ ] T-138 ACI parser for the compiler subset

Priority: P0 | Size: L | Depends on: T-122 | Wave 4 | Cloud fit: high (best-of-2 candidate)

Deliverables: parse ACI text emitted by `internal/config` (golden `testdata/runtime-acis.txt` + operator fixtures); reject unknown clauses rather than ignore.

Acceptance:
- [ ] All four runtime ACIs parse.
- [ ] Compiler golden operator ACIs parse.
- [ ] Injection characters in DN/attr are treated as data, not extra clauses.
- [ ] Out-of-grammar raw ACI fails with a stable error (C8).

## [ ] T-139 ACI evaluator and T-036 allow/deny matrix

Priority: P0 | Size: L | Depends on: T-138, T-126, T-128, T-135 | Wave 4 | Cloud fit: high

Deliverables: evaluate parsed ACIs on Search/Add/Modify/Delete/Compare; DM bypass; deny-wins per 389 observed; runtime account matrix from T-036.

Acceptance:
- [ ] Runtime can read people/groups and cannot read `userPassword`.
- [ ] Runtime can write people/groups except `aci`.
- [ ] Runtime can write `userPassword` on people.
- [ ] Runtime cannot modify engine-admin tree (`cn=config` absent is Delta D2; operation still `insufficientAccessRights`).
- [ ] Operator `groupdn` ACL allows a member and denies a non-member.

## [ ] T-140 Simple Paged Results control

Priority: P0 | Size: M | Depends on: T-127, T-130 | Wave 5 | Cloud fit: high

Deliverables: control OID `1.2.840.113556.1.4.319`; cookie integrity; advertised on Root DSE.

Acceptance:
- [ ] Page size 2 over 5 entries returns 3 pages and ends.
- [ ] Tampered cookie fails.
- [ ] Critical unknown control → `unavailableCriticalExtension`.

## [ ] T-141 RFC 4528 assertion control

Priority: P0 | Size: M | Depends on: T-128, T-130, T-132 | Wave 5 | Cloud fit: high

Deliverables: advertise `1.3.6.1.1.12`; transactional If-Match-style modify; do not advertise if not honored.

Acceptance:
- [ ] Matching assertion allows modify; failing assertion does not apply the write.
- [ ] Concurrent conflicting assertions: at most one commit (txn test).
- [ ] Root DSE lists the OID.

## [ ] T-142 WhoAmI extended operation

Priority: P0 | Size: S | Depends on: T-126, T-132 | Wave 5 | Cloud fit: high

Deliverables: RFC 4532 `1.3.6.1.4.1.4203.1.11.3`; advertise on Root DSE.

Acceptance:
- [ ] After simple bind, WhoAmI returns the bound DN (authzid form matching 389 observed or RFC; record Delta if formatting differs).
- [ ] T-115 `ldapwhoami` case can be pointed at native after T-148.

## [ ] T-143 `labldapd` daemon command

Priority: P0 | Size: M | Depends on: T-133, T-134, T-132 | Wave 5 | Cloud fit: medium

Deliverables: `cmd/labldapd` flags: config/engine-plan path, data dir, listen, TLS files, DM password file, health; structured logs; graceful shutdown.

Acceptance:
- [ ] `--help` documents flags; missing DM password file exits non-zero without protocol start.
- [ ] Process applies engine plan at start (suffix, policy, plugin hooks).
- [ ] Logs contain no secrets.

## [ ] T-144 Native bootstrap reconcilers

Priority: P0 | Size: L | Depends on: T-123, T-143, T-139 | Wave 5 | Cloud fit: medium

Deliverables: `internal/directory/native` implements **engine-plan read-back** reconcilers only (`BackendReconciler`, `TLSReconciler`, `PolicyReconciler`, `PluginReconciler`) per ADR-0009. Wait, tree, ACI, seed, verify, drift, and marker stay the existing LDAP-as-DM implementations (they already speak LDAP, not `dsconf`) wired by `cmd/labldap-bootstrap`. Fail closed if the daemon’s applied engine plan does not match. Known boundary amendment: `tools/importboundary` `forbiddenLDAPClient` currently bars `internal/directory/native` from importing `ldapclient` — this task amends that edge (native reconcilers read back over LDAP), with a boundary-test edge update.

Acceptance:
- [ ] `labldap-bootstrap apply` against a running `labldapd` with `engine: native` exits 0 on a minimal scenario.
- [ ] Mismatch (wrong suffix / policy) fails with a phase code, no marker commit.
- [ ] No `dsconf` invocation in the native path (test spy).

## [ ] T-145 Native image and compose-native profile

Priority: P0 | Size: L | Depends on: T-143 | Wave 5 | Cloud fit: medium (needs Docker)

Deliverables: `labldapd` image (non-root, read-only root, `/data` volume); `deploy/compose` native overlay replacing `dirsrv` with `labldapd`; `make image-native`; `make compose-up-native`; healthcheck.

Acceptance:
- [ ] Image contains no DM secret, no Docker socket, no source.
- [ ] `make compose-up-native` brings directory → bootstrap → control on loopback 3389/3636/8443.
- [ ] Floating tags absent from release compose.
- [ ] Pin base image by digest.

## [ ] T-146 Control-plane engine selection wiring

Priority: P0 | Size: M | Depends on: T-123, T-144 | Wave 5 | Cloud fit: high

Deliverables: `labldap serve` and `labldap-bootstrap` switch reconciler set on `EnginePlan.Engine`; runtime remains `ds389.Runtime` + `ldapclient` pointed at the configured LDAP URL. `native` before T-144 landed already fails closed (T-123); this task makes it succeed.

Acceptance:
- [ ] `engine: 389ds` path unchanged (existing IT still pass).
- [ ] `engine: native` uses native reconcilers only.
- [ ] Control still has no DM secret.

## [ ] T-147 Dual-engine parity harness

Priority: P0 | Size: L | Depends on: T-144, T-145 | Wave 6 | Cloud fit: medium

Deliverables: `test/parity` starts 389 (existing harness) and native (in-process or `labldapd`); compiles one scenario; runs Contract cases from the parity contract; `make test-parity`.

Acceptance:
- [ ] At least: seed bind, memberOf, nsAccountLock, runtime ACI allow/deny, paged search, LDAPS bind.
- [ ] Failures attach redacted logs from both engines.
- [ ] Secret scan of the run passes.
- [ ] D1 vendor strings are asserted different, not equal.

## [ ] T-148 Parametrize existing integration tests

Priority: P0 | Size: L | Depends on: T-147 | Wave 6 | Cloud fit: medium

Deliverables: run the T-043 observed suite and T-115 client matrix against native where Contract applies; skip Deltas by ID; `ldapwhoami` / `ldapsearch` / go-ldap / ldap3 vs native.

Acceptance:
- [ ] Documented skip list is only Delta/Excluded IDs from the parity contract.
- [ ] Compatibility report records native engine version beside 389.
- [ ] 389-only tests remain the default `make test-integration`.

## [ ] T-149 Differential fuzzing

Priority: P0 | Size: L | Depends on: T-124, T-127, T-138, T-147 | Wave 6 | Cloud fit: high (oracle step may be local)

Deliverables: shared corpus of BER/filter/DN/ACI; native must not panic; optional 389 comparison for parse-accept vs evaluate.

Acceptance:
- [ ] Native fuzz of codec, filter, ACI runs under `go test -fuzz` with a time-boxed CI job or documented nightly.
- [ ] No crashers committed; any 389/native parse divergence is a Delta or a native bug.

## [ ] T-150 Soak, leak, redaction, delta ledger, verify gate

Priority: P0 | Size: M | Depends on: T-147, T-148 | Wave 6 | Cloud fit: medium

Deliverables: short native soak (goroutine/FD/bolt growth); log redaction; `docs/design/parity-delta-log.md`; `make verify` includes native unit tests; M9 exit evidence.

Acceptance:
- [ ] No unbounded growth in the short soak.
- [ ] Delta ledger lists every accepted skip with test name.
- [ ] `make verify` green without requiring Docker native compose (compose-native stays `test-parity` / integration).
- [ ] README/docs only advertise native as ready after this task.

# Backlog completion checklist

- [x] All P0 tasks for M0–M8 are complete (v0.1.0).
- [ ] M9 (native engine) P0 tasks T-122–T-150 are complete.
- [ ] Every milestone exit criterion in `docs/10-implementation-plan.md` passes.
- [ ] Traceability matrix points to concrete test files or jobs.
- [ ] Accepted ADRs match implementation behavior.
- [ ] Full test logs are scanned for credentials and tokens.
- [ ] Release artifacts, digests, SBOMs, checksums, and documentation are published together.
