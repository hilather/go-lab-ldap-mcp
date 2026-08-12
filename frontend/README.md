# LabLDAP frontend

Placeholder for the React 19 / TypeScript / Vite administrative UI (T-095).
Do not add a large design system (OD-011).

Pinned (see `docs/toolchain.md`):

- Node.js `>=22.12.0` (`.node-version` is 22.14.0)
- `packageManager`: `pnpm@10.14.0`
- lockfile: `pnpm-lock.yaml`

```text
corepack enable
corepack prepare pnpm@10.14.0 --activate
pnpm install --frozen-lockfile
pnpm build
pnpm test
```
