# Toolchain pins

Recorded 2026-08-12 against the LabLDAP design baseline.

| Component | Design baseline | Pinned in this repo | Where |
| --- | --- | --- | --- |
| Go language | 1.26.x | `1.26` | `go.mod` `go` directive |
| Go toolchain | go1.26.5 (current stable 2026-08-12) | `go1.26.5` | `go.mod` `toolchain` |
| Node.js | 22.12 or later | `22.14.0` (host LTS; `>=22.12.0` engines) | `.node-version`, `.nvmrc`, `frontend/package.json` |
| pnpm | exact packageManager + lockfile | `pnpm@10.14.0` | `frontend/package.json` `packageManager`, `frontend/pnpm-lock.yaml` |
| React | 19.2 | `19.2.8` (T-095) | `frontend/package.json`, `frontend/pnpm-lock.yaml` |
| MCP Go SDK | v1.7.0+ / spec 2026-07-28 | `v1.7.0` (`StreamableHTTPOptions.Stateless=true`) | `go.mod`; `internal/mcpserver` |
| 389 DS image | pin by digest | `quay.io/389ds/dirsrv@sha256:f2851654c5df545cd893d84bea8d08c28dc25f0930493fbfed1d8a6eacf657f7` | `deploy/docker/dirsrv.digest`, `deploy/docker/dirsrv-image-contract.md` |
| Go builder image | pin by digest | `golang:1.26.5@sha256:705e964a93a2fd2e75c7d59bb7d781b57e30f12293ffde5175c69229e18fb678` | `deploy/docker/golang.digest` |
| Node builder image | pin by digest | `node:22.14.0-bookworm@sha256:e5ddf893cc6aeab0e5126e4edae35aa43893e2836d1d246140167ccc2616f5d7` | `deploy/docker/node.digest` |
| Control runtime image | pin by digest | `alpine:3.21@sha256:48b0309ca019d89d40f670aa1bc06e426dc0931948452e8491e3d65087abc07d` | `deploy/docker/alpine.digest` |
| LDAP client | `github.com/go-ldap/ldap/v3` | `v3.4.14` (T-028 bootstrap DM helper; T-046 runtime) | `go.mod`; only `internal/directory/ds389` and `internal/directory/ldapclient` may import it |
| OpenAPI Go generator | oapi-codegen (OD-009) | `v2.8.0` | `Makefile` `OAPI_CODEGEN_MOD`; models only |
| OpenAPI TypeScript types | openapi-typescript (OD-009) | `7.13.0` | `Makefile` `OPENAPI_TS_PKG` |
| Playwright | product acceptance (T-107) | `@playwright/test@1.62.1`, `@axe-core/playwright@4.10.2` | `test/e2e/package.json` |
| govulncheck | reachable vulns (T-007 / T-118) | `golang.org/x/vuln/cmd/govulncheck@v1.1.4` | `Makefile` `GOVULNCHECK_MOD` |

No deviation from the Go or Node baseline. Frontend scaffold (T-095): React 19.2.8, Vite 8.2.1, TanStack Query 5.101.4, React Router 8.3.0, React Hook Form 7.85.0, Zod 4.4.3, openapi-fetch 0.17.0. `pnpm install --frozen-lockfile && pnpm build` must succeed from the committed lockfile.

## Developer tools

Make installs or invokes tools at versions listed in the `Makefile`. Do not `go install` or `npx` a floating `@latest` tag.

CI (`/.github/workflows/ci.yml`) installs host `ldap-utils` and `python3-venv`
before `make test-integration`. The T-115 cases fail (they do not skip) when
those tools are missing on GitHub Actions. Locally the same cases skip if the
binary is absent.

The public site is GitHub Pages from `docs/`
(https://hilather.github.io/go-lab-ldap-mcp/). Enable it once with
`build_type=workflow` (Settings → Pages → GitHub Actions). The deploy
workflow must not pass `enablement: true`: `GITHUB_TOKEN` cannot create
the Pages site.

## Dependency update policy

- Go: bump the `toolchain` line when a new 1.26.x patch is adopted; bump the `go` line only for a new language version. Record the change here.
- Node: keep `engines.node` at `>=22.12.0`. Change `.node-version` only to another supported 22.x release and record it here.
- pnpm: change `packageManager` and regenerate `pnpm-lock.yaml` together.
- Application dependencies (when added) require `go.sum` / `pnpm-lock.yaml` in the same commit. Critical vulnerabilities fail CI (see `docs/security/dependency-policy.md`).
- Do not invent a distribution LICENSE (OD-003). Dependency license notices still apply.
