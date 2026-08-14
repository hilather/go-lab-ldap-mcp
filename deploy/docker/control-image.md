# labldap-control image contract

Recorded: 2026-08-14  
Tasks: T-108, T-109  
Image: `labldap-control:dev` (OD-004; do not push)

## Build

Multi-stage:

1. Pinned `node:22.14.0-bookworm` builds `frontend/` with `pnpm@10.14.0 --frozen-lockfile`.
2. Pinned `golang:1.26.5` copies `frontend/dist` over `internal/web/dist` and links a static `labldap`.
3. Pinned `alpine:3.21` runtime: `ca-certificates`, `wget` (HEALTHCHECK), user `65532`, no source tree.

Builder digest files: `deploy/docker/{golang,node,alpine}.digest`. 389 DS remains `deploy/docker/dirsrv.digest`.

`make image` passes the same `VERSION` / `REVISION` / `BUILT_AT` as `make image-bootstrap` so `labldap version` and `labldap-bootstrap version` report compatible fields.

## Runtime hardening

| Setting | Value |
| --- | --- |
| User | `65532:65532` (`labldap`) |
| Root filesystem | read-only in Compose |
| Capabilities | `cap_drop: ALL` |
| Privileges | `no-new-privileges:true` |
| Writable tmpfs | `/tmp` only (`uid=65532,gid=65532,mode=1777`) |
| Directory Manager | never present (no env, no mount, not baked) |
| Docker socket | never mounted |
| Secrets | mounts only; `.dockerignore` excludes `/secrets` and fixture passwords |

HEALTHCHECK is `GET /health` (liveness; not LDAP). Compose healthcheck must stay on `/health`, not `/health/ready`.

## Smoke

`make image` builds the tag, prints `version`, and runs a read-only / dropped-cap / no-new-privileges placeholder listener against `/health`.
