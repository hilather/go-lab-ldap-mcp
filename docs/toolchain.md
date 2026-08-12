# Toolchain pins

Recorded 2026-08-12 against the LabLDAP design baseline.

| Component | Design baseline | Pinned in this repo | Where |
| --- | --- | --- | --- |
| Go language | 1.26.x | `1.26` | `go.mod` `go` directive |
| Go toolchain | go1.26.5 (current stable 2026-08-12) | `go1.26.5` | `go.mod` `toolchain` |
| Node.js | 22.12 or later | `22.14.0` (host LTS; `>=22.12.0` engines) | `.node-version`, `.nvmrc`, `frontend/package.json` |
| pnpm | exact packageManager + lockfile | `pnpm@10.14.0` | `frontend/package.json` `packageManager`, `frontend/pnpm-lock.yaml` |
| React | 19.2 | not yet (T-095) | placeholder frontend only |
| MCP Go SDK | v1.7.0+ / spec 2026-07-28 | not yet (T-085) | — |
| 389 DS image | pin by digest | `quay.io/389ds/dirsrv@sha256:f2851654c5df545cd893d84bea8d08c28dc25f0930493fbfed1d8a6eacf657f7` | `deploy/docker/dirsrv.digest`, `deploy/docker/dirsrv-image-contract.md` |

No deviation from the Go or Node baseline. The frontend is an empty-app placeholder: `pnpm install --frozen-lockfile && pnpm build` must succeed without React until T-095.

## Developer tools

Make installs or invokes tools at versions listed in the `Makefile`. Do not `go install` or `npx` a floating `@latest` tag.

## Dependency update policy

- Go: bump the `toolchain` line when a new 1.26.x patch is adopted; bump the `go` line only for a new language version. Record the change here.
- Node: keep `engines.node` at `>=22.12.0`. Change `.node-version` only to another supported 22.x release and record it here.
- pnpm: change `packageManager` and regenerate `pnpm-lock.yaml` together.
- Application dependencies (when added) require `go.sum` / `pnpm-lock.yaml` in the same commit. Critical vulnerabilities fail CI (see `docs/security/dependency-policy.md`).
- Do not invent a distribution LICENSE (OD-003). Dependency license notices still apply.
