# Deployment

Dev Compose (T-042) is directory → bootstrap one-shot → placeholder control.
Hardened `labldap-control:dev` (T-108) and matching-version bootstrap (T-109)
are built by `make image` / `make image-bootstrap`. Ephemeral/persistent
Compose profiles land in T-110/T-111. Release files must pin images by
digest, never a floating tag.

## Images

| Image | Make target | Notes |
| --- | --- | --- |
| `labldap-bootstrap:dev` | `make image-bootstrap` | Static `labldap-bootstrap` on the pinned 389 DS digest, same VERSION as control. Do not push (OD-004). |
| `labldap-control:placeholder` | `make image-control-placeholder` | Thin T-042 process (`labldap serve --placeholder`). Not used by `make image`. |
| `labldap-control:dev` | `make image` | Hardened multi-stage frontend+Go image. Non-root, CA bundle, HEALTHCHECK `/health`. |

Builder pins: [`deploy/docker/builder-images.md`](https://github.com/hilather/go-lab-ldap-mcp/blob/main/deploy/docker/builder-images.md).
Control contract: [`deploy/docker/control-image.md`](https://github.com/hilather/go-lab-ldap-mcp/blob/main/deploy/docker/control-image.md).

The bootstrap image keeps `dsconf` / `dsctl`. Secrets are mounts only. Both
images stamp `internal/observability` version/revision so `version` output
is comparable. Compose still uses the T-042 placeholder until T-110.

## Compose

```text
make compose-up
make compose-down
```

`make compose-up` writes `secrets/directory.env` and `secrets/dm.pw` (mode 0600)
if they are missing (KD-R20). The directory service uses the env_file;
bootstrap uses `--directory-manager-password-file`; control never receives
Directory Manager.

Placeholder control binds `0.0.0.0:8443` inside the container so Docker can
forward to eth0. The host publish is loopback-only (`127.0.0.1:8443:8443`).
`GET /health` is liveness. `GET /health/ready` returns 503. `make compose-reset`
stays pending until T-110.
