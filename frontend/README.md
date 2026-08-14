# LabLDAP frontend

React 19.2 / TypeScript / Vite administrative UI (T-095–T-097).
Semantic HTML only — no large design system (OD-011).

Pinned (see [docs/toolchain.md](https://github.com/hilather/go-lab-ldap-mcp/blob/main/docs/toolchain.md)):

- Node.js `>=22.12.0` (`.node-version` is 22.14.0)
- `packageManager`: `pnpm@10.14.0`
- lockfile: `pnpm-lock.yaml`
- React `19.2.8`, Vite `8.2.1`

Resource models come from [`api/generated/typescript/schema.d.ts`](https://github.com/hilather/go-lab-ldap-mcp/blob/main/api/generated/typescript/schema.d.ts)
via `openapi-fetch`. Do not hand-write duplicate User/Group types.

## Session security

Sign-in (`/login`) posts the static token to `POST /api/v1/session` and
keeps only the returned CSRF secret in process memory. The session cookie
is `HttpOnly`. Do not write bearer tokens or CSRF secrets to
`localStorage`, `sessionStorage`, IndexedDB, or the URL.

Logout and session expiry clear TanStack Query directory data and return
to `/login`. A reload keeps the cookie but drops the CSRF secret; the
shell tells the operator to sign in again before mutations.

## Dashboard

`/` shows scenario status, engine, baseline, transport, an insecurity
banner when the tab is not a secure context or cleartext LDAP is
advertised, scope-aware quick actions, recent audit events, and a
directory-outage view. Status uses a symbol plus a text label, not color
alone. User and group CRUD pages are later tasks.

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
