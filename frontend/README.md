# LabLDAP frontend

React 19.2 / TypeScript / Vite administrative UI (T-095–T-107).
Semantic HTML only — no large design system (OD-011). Production CSP is
`script-src 'self'` with no unsafe-inline script exception. LDAP values
are rendered as text.

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

Logout and idle expiry call `DELETE /api/v1/session` **before** dropping
the in-memory CSRF secret, then clear TanStack Query directory data.
A reload keeps the cookie but drops the CSRF secret. That is not a
complete browser session: `/login` stays on the token form (it does not
bounce back to `/`), Sign out stays disabled, and the shell links to
`/login` so the operator can rotate a new CSRF. A 403 from DELETE is
not treated as a successful logout.

## Dashboard

`/` shows scenario status, engine, baseline, transport, an insecurity
banner when the tab is not a secure context or cleartext LDAP is
advertised, scope-aware quick actions, recent audit events, and a
directory-outage view. Status uses a symbol plus a text label, not color
alone.

## Users and groups

`/users`, `/users/new`, and `/users/:id` list, create, edit, enable,
disable, set password, and delete users. Mutations send the current
revision (`If-Match` quoted hex, or `revision` on the password body).
A 412 conflict offers refresh and does not overwrite. Delete requires
typing the exact user ID. Read-only sessions cannot submit create.
Password fields clear after success and failure.

`/groups`, `/groups/new`, and `/groups/:id` list and create groups with a
required initial member chosen through bounded server search. Empty
`groupOfNames` is rejected; the UI does not insert a fake member. Group
detail supports add, remove, and replace membership with added / removed
/ unchanged / rejected summaries. Cycle errors leave the group unchanged.
There is no group-attribute edit form (no `PATCH /groups/{id}`).

## Search, bind test, schema, audit, reset, export

`/search` is an explicit-submit console (base, scope, filter, attributes, page
size). Typing does not run LDAP. Attribute controls are an allowlist;
`userPassword` and other forbidden names cannot be requested. Results expand
for a redacted LDIF snippet.

`/auth-test` posts a bind diagnostic and clears the password field after the
request. Failures do not distinguish unknown identity from a wrong password.
`/schema` is a read-only, keyboard-navigable Root DSE and schema browser.

`/audit` lists the in-memory ring with action/actor filters, request-ID copy,
and a retention notice. Actor and target are non-secret identifiers; secret-
looking values are replaced with `[redacted]`. Missing `audit:read` is a
permission state.

`/reset` requires `lab:reset`, the exact compiled scenario name, and the
current revision. Duplicate submits are blocked while a reset is running.
Completion invalidates baseline, users, groups, capabilities, and audit.
`/export` downloads authenticated LDIF. `/diagnostics` is a secret-free
status view.

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
