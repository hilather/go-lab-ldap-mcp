# LabLDAP frontend

React 19.2 / TypeScript / Vite administrative UI scaffold (T-095).
Semantic HTML only — no large design system (OD-011). Login, shell, and
dashboard workflows are later tasks (T-096+).

Pinned (see [docs/toolchain.md](https://github.com/hilather/go-lab-ldap-mcp/blob/main/docs/toolchain.md)):

- Node.js `>=22.12.0` (`.node-version` is 22.14.0)
- `packageManager`: `pnpm@10.14.0`
- lockfile: `pnpm-lock.yaml`
- React `19.2.8`, Vite `8.2.1`

Resource models come from [`api/generated/typescript/schema.d.ts`](https://github.com/hilather/go-lab-ldap-mcp/blob/main/api/generated/typescript/schema.d.ts)
via `openapi-fetch`. Do not hand-write duplicate User/Group types.

Bearer tokens stay in process memory only. Do not write them to
`localStorage`, `sessionStorage`, IndexedDB, or the URL.

```text
corepack enable
corepack prepare pnpm@10.14.0 --activate
pnpm install --frozen-lockfile
pnpm build
pnpm test
```

`pnpm build` writes hashed assets to `frontend/dist`. The Go control
plane embeds `internal/web/dist` (placeholder until the T-108 image
build copies this production output) and serves hashed files with
immutable cache headers plus `index.html` SPA fallback.
