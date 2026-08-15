# Deploy

How to build, run, and operate LabLDAP on a single host.

LabLDAP is a **laboratory**. Images stay local. The management listener is
bound to loopback. There is no public registry push and no Kubernetes chart
in v0.1.0.

For the product contract see [Operator guide](../operations/operator-guide.md).
This page is the short path.

## Host requirements

| Need | Minimum |
| --- | --- |
| OS | Linux `amd64` (advertised). `arm64` is not advertised. |
| Docker Engine | 24+ |
| Compose | v2.24+ |
| Disk | enough for two local images plus 389 DS data |
| Ports on loopback | `8443` (management), `3389` (LDAP), `3636` (LDAPS) |

Optional for from-source work: Go 1.26 (toolchain `go1.26.5`), Node 22.12+,
pnpm. Pins live in [docs/toolchain.md](../toolchain.md).

## Topology

```
                    loopback
                 ┌─────────────┐
  browser / curl │ :8443  UI   │
  MCP HTTP       │        REST │──── labldap (control)
  metrics        │        MCP  │         │
                 └─────────────┘         │ runtime account
                                         ▼
  ldapsearch     :3389 / :3636      389 Directory Server
                                         ▲
                         one-shot        │ Directory Manager
                      labldap-bootstrap ─┘  (secret file, then gone)
```

Three compose roles:

| Service | Image | Lifetime | Privilege |
| --- | --- | --- | --- |
| `directory` | pinned `quay.io/389ds/dirsrv` | long-running | owns `/data` |
| `bootstrap` | `labldap-bootstrap:dev` | one-shot | DM via `--directory-manager-password-file` |
| `control` | `labldap-control:dev` | long-running | restricted account, no DM, no Docker socket |
| `secret-prep` | `labldap-control:dev` | one-shot | copies secret files into a 0400 volume for uid 65532 |

Control never receives Directory Manager. Bootstrap never stays up.

## One command

```bash
make compose-up
```

Ephemeral. `/data` is tmpfs. Recreating the directory container starts empty;
bootstrap reapplies the baseline. Host swap can still hold pages — this is
not a forensic wipe.

```bash
make compose-up-persistent
```

Named volume. Runtime entries survive restart. After first boot the helper
imports the lab CA and server cert into 389 DS and restarts the directory
for NSS reload.

```bash
make compose-down
make compose-reset    # down -v, then compose-up
```

`make compose-up` runs `tools/composepreflight`, generates secrets, and
generates TLS if they are missing.

## Images

All local. Do not push.

```bash
make image-bootstrap   # labldap-bootstrap:dev
make image             # labldap-control:dev
```

`make image` also checks that control and bootstrap report the same
`version=` and smokes `GET /health`.

| Image | What it is |
| --- | --- |
| `labldap-bootstrap:dev` | static helper, pinned 389 DS digest, same VERSION as control |
| `labldap-control:dev` | multi-stage frontend + Go, non-root, CA bundle, HEALTHCHECK `/health` |
| `labldap-control:placeholder` | thin process only — **not** what compose-up runs |

Release compose files pin **digests**, never floating tags.

## Secrets

Generated on first `compose-up`, mode `0600`, gitignored.

```bash
go run ./tools/setupsecrets --dir secrets          # create if missing
go run ./tools/setupsecrets --dir secrets --force  # rotate
go run ./tools/setupsecrets --dir secrets --print  # show names, not values
```

Typical files:

| File | Used by |
| --- | --- |
| `secrets/dm.pw` | bootstrap only |
| `secrets/directory.env` | 389 DS container |
| `secrets/runtime-ldap` | control's directory bind |
| `secrets/token-admin` | UI / REST / MCP bearer |
| `secrets/user-alice` | seeded user password |

`secret-prep` copies token and password files into a volume as uid `65532`,
mode `0400`. After rotation, recreate that service so control sees the new
bytes.

Never pass `--directory-manager-password` on a command line. Always a file.

## TLS

```bash
go run ./tools/setuptls generate --dir secrets/tls --host directory
go run ./tools/setuptls generate --dir secrets/tls --host management
```

- Private CA key stays on the **host** (`secrets/tls/ca.key`). It is not
  mounted into containers.
- Ephemeral: trust `secrets/tls/instance-ca.crt`. tmpfs `/data` cannot take
  `dsctl tls import-*`.
- Persistent: `setuptls import` then 389 DS picks up the lab CA / server
  cert after first boot.

Wrong CA or SAN: connections fail closed.

Management TLS `mode: generated` in the example scenario is a lab
certificate, not a public CA. Keep :8443 on loopback.

## Compose files

Under [`deploy/compose/`](../../deploy/compose/):

| File | Role |
| --- | --- |
| `compose.yaml` | base: directory, bootstrap, secret-prep, control |
| `compose.ephemeral.yaml` | tmpfs `/data` |
| `compose.persistent.yaml` | named volume + TLS import |
| `scenario.yaml` | compiled baseline for ephemeral |
| `scenario.persistent.yaml` | baseline for persistent |

Published ports are **loopback only**:

```
127.0.0.1:8443 → control (0.0.0.0:8443 in-container)
127.0.0.1:3389 → LDAP
127.0.0.1:3636 → LDAPS
```

Minimum resource guidance (not enforced everywhere): directory 512Mi / 1
CPU, control 256Mi, bootstrap 256Mi.

## From source, no compose

Useful when you already have a 389 DS and a compiled scenario:

```bash
go run ./cmd/labldap-bootstrap --help
go run ./cmd/labldap serve --config config/examples/example-lab.yaml
go run ./cmd/labldap mcp-stdio --config FILE --token-file secrets/token-admin
```

Directory flags: `--ldap-url`, `--directory-ca-file`, `--directory-host`
(or `LABLDAP_LDAP_URL`, `LABLDAP_DIRECTORY_CA_FILE`,
`LABLDAP_DIRECTORY_HOST`).

Logs go to stderr. `LABLDAP_LOG_FORMAT=json` for JSON.

`--placeholder` starts the process without an LDAP pool. That is a
development crutch, not a lab.

## Soft reset vs hard reset

| Kind | How | What it does |
| --- | --- | --- |
| Soft | UI Reset, `POST /api/v1/reset`, `ldap_reset_suffix` | restore compiled suffix |
| Hard | `make compose-reset` | delete volumes, start over |

Soft reset needs `lab:reset`, the exact scenario name, and the current
revision. Hard reset is not on the API.

`docker compose restart directory` on a persistent lab can drop published
ports. Prefer `docker compose up -d --wait directory` and wait for
`/health/ready`.

## Health and metrics

```bash
curl -sk https://127.0.0.1:8443/health
curl -sk https://127.0.0.1:8443/health/ready
curl -sk https://127.0.0.1:8443/metrics
```

Liveness never queries LDAP. Readiness does. The image HEALTHCHECK hits
`/health`.

## What this release does not do

- No image push, no Helm, no cloud module
- No multi-suffix, no multi-instance 389 DS
- No Active Directory emulation
- No project `LICENSE` file yet
- Signing (`cosign`) is optional and not performed
- `linux/arm64` is not an advertised platform

If you need those, they are product decisions, not missing flags.

## Next

- [Quick start](quickstart.md)
- [User guide](user-guide.md)
- [Troubleshooting](../operations/troubleshooting.md)
- [Release notes](../release/notes.md)
