# ADR NNNN: Title

Use this template for a new architecture decision. Copy it to `docs/adr/NNNN-short-kebab-title.md`.

**Stubs are not ADRs.** Files matching `docs/adr/*.stub.md` are title-only placeholders. They do **not** occupy the [AGENTS.md](https://github.com/hilather/go-lab-ldap-mcp/blob/main/AGENTS.md) rank-1 slot and must not be cited as accepted decisions. Recovered or newly written ADRs replace a stub by dropping the `.stub` suffix and filling every section below.

## Status

One of:

- Proposed
- Accepted
- Deprecated
- Superseded by ADR-NNNN

Date: YYYY-MM-DD

Deciders: names or “repository owner”

Related tasks: T-XXX

Related ADRs: ADR-NNNN (optional)

## Context

What problem, constraint, or discovery forces a decision? Include the alternatives that were on the table and any security, compatibility, or source-of-truth implications. Cite the documents that disagree or the implementation evidence that the existing design does not cover.

Do not change a public contract, engine choice, privilege boundary, or reset model without completing this ADR.

## Decision

The change we are making, stated so an implementer can follow it without rereading the discussion. Name the rejected option if silence would be ambiguous.

## Consequences

### Positive

What becomes easier, safer, or more explicit.

### Negative

What becomes harder, slower, or more constrained. Residual risk stays here, not in a later commit message.

### Neutral / follow-up

Documentation, migration, compatibility notes, and tasks that must land with or immediately after the decision.

## Alternatives considered

| Option | Why not chosen |
| --- | --- |
| … | … |

## Notes

- Accepted ADRs outrank other repository documents.
- Security defaults may become stricter in a minor release; insecure behavior must never become the silent default.
- Do not invent rejected options or consequence text when only recovering a stub title. Write a real ADR or leave the stub in place.
