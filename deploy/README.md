# Deployment

Start here: **[docs/guides/deploy.md](../docs/guides/deploy.md)**.
Operator package: [docs/operations/operator-guide.md](../docs/operations/operator-guide.md).
Release notes: [docs/release/notes.md](../docs/release/notes.md).

Compose topology: directory (`labldapd` default, or pinned 389 via
`compose.389ds.yaml`) → bootstrap one-shot → hardened `labldap-control:dev`.

Release files pin images by digest, never a floating tag. Control never
receives Directory Manager and never mounts the Docker socket.

## Images

| Image | Make target | Notes |
| --- | --- | --- |
| `labldapd:dev` | `make image-native` | Native directory engine. Default `compose-up`. Do not push (OD-004). |
| `labldap-bootstrap:dev` | `make image-bootstrap` | Static `labldap-bootstrap` on the pinned 389 DS digest, same VERSION as control. Do not push (OD-004). |
| `labldap-control:placeholder` | `make image-control-placeholder` | Thin T-042 process. Not used by `make compose-up`. |
| `labldap-control:dev` | `make image` | Hardened multi-stage frontend+Go image. Non-root, CA bundle, HEALTHCHECK `/health`. |

Builder pins: [`deploy/docker/builder-images.md`](https://github.com/hilather/go-lab-ldap-mcp/blob/main/deploy/docker/builder-images.md).
Control contract: [`deploy/docker/control-image.md`](https://github.com/hilather/go-lab-ldap-mcp/blob/main/deploy/docker/control-image.md).

The bootstrap image keeps `dsconf` / `dsctl`. Secrets are mounts only. Both
images stamp `internal/observability` version/revision so `version` output
is comparable.

## Compose

```text
make compose-up              # native labldapd; ephemeral 2GiB tmpfs /data
make compose-up-persistent   # native; named volume
make compose-up-389ds        # 389 oracle/rollback; publish instance CA
make compose-down
make compose-reset           # operator hard reset: down -v, then compose-up
```

`make compose-up` (ephemeral, native) generates gitignored secrets and a
lab CA, starts `labldapd`, then bootstrap and control. Ephemeral tmpfs
`/data` remounts empty on container restart. Size stays **2GiB** (RQ-5).

`make compose-up-389ds` restores pinned 389 DS and publishes the
**instance CA** to `secrets/tls/instance-ca.crt`. Persistent 389
(`compose-up-389ds-persistent`) still uses `dsctl tls import-*` after
first boot.

The directory service uses `secrets/directory.env`. Bootstrap uses
`--directory-manager-password-file`. Control never receives Directory
Manager. The private CA key stays on the host under `secrets/tls/ca.key`
and is not mounted into any runtime service.

Host publishes are loopback-only:

- `127.0.0.1:8443` management (control)
- `127.0.0.1:3389` LDAP
- `127.0.0.1:3636` LDAPS

In-container control listens on `0.0.0.0:8443` so Docker DNAT works.
`labldap serve --config` terminates TLS (`tls.mode: generated` uses an
ephemeral self-signed management cert). Probe with
`wget --no-check-certificate https://127.0.0.1:8443/health`.
`GET /health` is liveness. `GET /health/ready` requires runtime bind and
baseline match.

### Ephemeral vs persistent

Ephemeral (`compose.ephemeral.yaml`) uses a **tmpfs-backed Docker volume**
for `/data`. UID 65532, GID 65532, mode 0750, size **2GiB** (RQ-5). The
389 rollback overlay (`compose.389ds-ephemeral.yaml`) keeps UID 389 and
the same 2GiB size. Runtime entries disappear after volume unmount
or `compose-reset`. Ordinary container recreate that keeps the volume
object may remount an empty tmpfs.

**Host swap can still persist tmpfs pages** unless the host is configured
otherwise. Ephemeral mode is not a forensic wipe (non-negotiable 7).

Persistent (`compose.persistent.yaml`) uses a named volume. Ordinary
restart keeps runtime entries. Soft reset (`POST /api/v1/reset` with
`lab:reset`) restores the compiled baseline and does **not** remove the
volume. Volume removal is a destructive operator action
(`make compose-reset` / `docker compose down -v`) and is not exposed
through REST or MCP.

### Helpers

```text
go run ./tools/setupsecrets --dir secrets
go run ./tools/setupsecrets --dir secrets --force   # rotate
go run ./tools/setupsecrets --dir secrets --print   # print values (off by default)
go run ./tools/setuptls generate --dir secrets/tls --host directory
go run ./tools/setuptls generate --dir secrets/tls --management
go run ./tools/setuptls publish --out secrets/tls/instance-ca.crt
go run ./tools/setuptls import --dir secrets/tls --project labldap
go run ./tools/composepreflight
```

Existing secret files are not overwritten unless `--force` is set.
All generated secret files are mode 0600 on the host. A one-shot
`secret-prep` copies token/password files into a volume as uid 65532
mode 0400 (Compose file secrets ignore uid/mode without Swarm).
`make compose-up` / `compose-up-persistent` `--force-recreate` that
one-shot after `setupsecrets --force` so `control-secrets` is not stale.
Native labs mount `secrets/tls/ca.crt` as files. `setuptls publish` /
`import` (`dsctl tls import-*`) are 389 rollback only
(`compose-up-389ds` / `compose-up-389ds-persistent`). A wrong CA or SAN
fails closed at control/bootstrap TLS verify.

### Resource guidance

Directory ≈ 512Mi / 1 CPU. Control ≈ 256Mi. Bootstrap ≈ 256Mi (one-shot).

### Minimum versions (OD-020)

Docker Engine **24+** and Compose **v2.24+** (secrets/`env_file`, health
dependencies, tmpfs uid/gid/mode/size, `service_completed_successfully`,
read-only + `cap_drop` + `no-new-privileges`). `make compose-up` runs
`tools/composepreflight`. Observed on this work: Engine 29.1.3, Compose
v2.40.3.
