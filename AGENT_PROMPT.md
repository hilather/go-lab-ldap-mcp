# LabLDAP Implementation Agent Prompt

Use this prompt when handing the package to an autonomous coding agent. The package files remain authoritative; this prompt is only the execution entry point.

## Mission

Implement LabLDAP from the design package in this repository. LabLDAP is a disposable laboratory LDAP environment built from:

- 389 Directory Server as the LDAP engine and source of truth.
- A Go bootstrap command for privileged, one-shot directory configuration.
- A long-running Go control plane for REST, MCP, UI hosting, authorization, reset, export, audit, and health.
- A React and TypeScript administrative UI.
- Docker Compose for local and laboratory deployment.

Do not implement a new LDAP wire-protocol server.

## Required startup procedure

1. Read `README.md`.
2. Read `AGENTS.md` in full and treat it as binding.
3. Read `docs/13-open-decisions.md`; apply its recorded defaults unless the repository owner has supplied a different decision.
4. Read all accepted ADRs under `docs/adr/`.
5. Inspect `TASKS.md` and determine the first unchecked task whose dependencies are complete.
6. Read every design document linked by that task.
7. Implement only that task and any inseparable prerequisite correction. Do not silently broaden scope.

## Execution rules

- Work in task-ID order unless `TASKS.md` explicitly permits parallel work.
- Keep 389 DS as the only source of truth for directory entries.
- Keep Directory Manager credentials out of the long-running control service.
- Never mount the Docker socket into an application container.
- Route REST, MCP, and UI actions through the same application services and authorization policy.
- Treat password values, API tokens, session IDs, bind credentials, and secret-file contents as sensitive at every boundary.
- Use a real 389 DS container for all engine behavior and integration acceptance tests.
- Do not replace required integration tests with mocks.
- Generate public API artifacts through committed generation commands; do not hand-edit generated files.
- Add an ADR before changing a non-negotiable decision or public contract.
- Do not mark a task complete when an acceptance test was skipped or cannot run.

## Per-task loop

For each selected task:

1. Restate its acceptance criteria.
2. Identify the affected requirement IDs and design sections.
3. Add or update tests first where practical.
4. Implement the smallest complete change.
5. Run formatting, linting, generation drift checks, unit tests, and every relevant real-engine, contract, security, or browser test.
6. Update documentation and examples when behavior or contracts change.
7. Update the task checkbox only after all criteria pass.
8. Produce the report format required by `AGENTS.md`.
9. Continue to the next eligible task only when the environment and assigned work scope permit it.

## Blocked-work protocol

A task is blocked only when proceeding would require unavailable credentials, an owner-only decision identified in `docs/13-open-decisions.md`, an unsupported environment capability, or a change to an accepted architectural decision.

When blocked:

1. Record the exact failed command, observable result, and relevant logs with secrets redacted.
2. Distinguish an implementation defect from an environment limitation.
3. Add a narrowly scoped proposed ADR when a design decision is required.
4. Mark the task `[!]` and state the dependency needed to unblock it.
5. Continue only with another task that has no dependency on the blocked behavior and cannot create merge conflicts or contract drift.

Do not invent passing results, production support, upstream behavior, or security guarantees.

## Completion target

The implementation is complete only when every P0 task required by the first usable release is checked, all milestone gates pass, the traceability matrix is satisfied, the real-389-DS compatibility suite passes in ephemeral and persistent modes, release images are pinned and reproducible, and `make verify` succeeds from a clean checkout.

## Required task report

```text
Task: T-XXX
Result: complete | partial | blocked
Requirements covered: ...
Files changed: ...
Tests run: ...
Acceptance criteria: pass/fail by item
Security notes: ...
Design deviations or ADRs: ...
Follow-up tasks: ...
```
