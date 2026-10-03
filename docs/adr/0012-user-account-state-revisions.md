# ADR 0012: Shared opaque revisions include public account state

## Status

Proposed for owner review

Date: 2026-10-03

Related tasks: project code review; T-067 and account-state workflows

## Context

User and account-state endpoints currently share a revision computed from
public user profile fields. Account-state actions also expose `locked` and
`mustChange`, but these values do not enter the revision. A lock or password
expiry therefore leaves the revision unchanged, and an older `If-Match` can
silently reverse a newer account action. LDAP assertion controls only protect
the read-to-write interval of one request, not this stale-client case.

## Decision proposed

Keep one opaque revision shared by user and account-state endpoints. The LDAP
adapter hashes the canonical public user revision together with the exposed
`locked` and `mustChange` booleans. Every user read requests the same account
stamps so both endpoints return the same token. Do not add response fields or
include passwords, hashes, raw timestamps, or other secret values.

The existing user-revision workflow remains usable for account actions.
Opaque revision values rotate on upgrade; clients must refresh before
mutating. This changes revision contents without changing REST paths, MCP
tool schemas, or the configuration version.

## Consequences

- Stale profile and account mutations fail after lock or expiry transitions.
- Existing user and account clients continue using the same revision token.
- A password ageing into `mustChange` changes its public state and revision.
- Tokens cached across the upgrade are stale and require a fresh read.
- Repeated actions that leave all public state unchanged remain idempotent.

## Alternatives considered

| Option | Why not chosen |
| --- | --- |
| Independent account-state revisions | Breaks existing clients that use the user revision for account actions. |
| Hash LDAP timestamps or password material | Violates the nonsecret canonical public-state revision model. |
| Keep only LDAP assertion controls | Does not detect state changed before a stale request starts. |

## Validation

Dual-engine integration asserts that locking and expiry change the shared
revision, old revisions fail, and freshly read user/account tokens agree.
