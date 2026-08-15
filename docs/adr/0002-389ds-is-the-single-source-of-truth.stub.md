# ADR 0002 (stub)

**Status:** title only — **not** an accepted ADR. The source-of-truth principle
(directory data lives in the engine, not a Go overlay map) is **preserved** by
[ADR-0008](0008-dual-directory-engines.md). Engine identity is no longer 389-only.

**Title (from MANIFEST.md):** Decision that all directory data and runtime
changes live in 389 DS.

**Matching non-negotiable:** Users, groups, memberships, and runtime mutations
live in the selected engine (389 DS or native `labldapd`). The control plane
is not an overlay source of truth.

Do not invent rejected options, consequences, or full ADR body text. Do not
cite this stub as an accepted decision.
