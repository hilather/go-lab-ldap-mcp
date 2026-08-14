# Deployment

Dev Compose (T-042) is directory → bootstrap one-shot → placeholder control.
Release images and ephemeral/persistent profiles land in M8. Release files
must pin the 389 DS image by digest, never a floating tag.

## Images

| Image | Make target | Notes |
| --- | --- | --- |
| `labldap-bootstrap:dev` | `make image-bootstrap` | Static `labldap-bootstrap` on the pinned 389 DS digest. Do not push (OD-004). |
| `labldap-control:placeholder` | `make image-control-placeholder` | Thin T-042 process (`labldap serve --placeholder`). Not T-108. |
| `labldap-control:dev` | `make image` | Prints `PENDING:control-image` until T-108. |

The bootstrap image keeps `dsconf` / `dsctl`. Secrets are mounts only.

## Compose

```text
make compose-up
make compose-down
```

`make compose-up` writes `secrets/directory.env` and `secrets/dm.pw` (mode 0600)
if they are missing (KD-R20). The directory service uses the env_file;
bootstrap uses `--directory-manager-password-file`; control never receives
Directory Manager.

Placeholder control listens on `LABLDAP_LISTEN` (`127.0.0.1:8443` in Compose).
`GET /health` is liveness. `GET /health/ready` returns 503. `make compose-reset`
stays pending until T-110.
