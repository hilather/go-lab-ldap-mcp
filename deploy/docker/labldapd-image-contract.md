# labldapd image contract

Recorded: 2026-08-15
Tasks: T-145 (image + Compose native profile); CLI surface owned by T-143
Image: `labldapd:dev` (OD-004; do not push)

## Build

Multi-stage, mirroring `Dockerfile.control` / `Dockerfile.bootstrap`:

1. Pinned `golang:1.26.5` (`deploy/docker/golang.digest`) links a static
   `CGO_ENABLED=0` `labldapd` from `./cmd/labldapd` with the shared
   `internal/observability` version/revision/builtAt ldflags.
2. Pinned `alpine:3.21` runtime from **`deploy/docker/labldapd.digest`** (the
   native-engine runtime base pin of record, so the engine base can advance
   independently of the control image's `alpine.digest`): `ca-certificates`,
   `wget` (HEALTHCHECK), user `65532`, no source tree, no package cache.

`make image-native` passes the same `VERSION` / `REVISION` / `BUILT_AT` as
`make image` / `make image-bootstrap` so `labldapd version` reports
compatible fields. `test/imagecontract` asserts the Dockerfile ARG defaults
match the digest files.

## Runtime hardening

| Setting | Value |
| --- | --- |
| User | `65532:65532` (`labldapd`; same non-root uid convention as control) |
| Root filesystem | read-only in Compose (`compose.native.yaml`) |
| Capabilities | `cap_drop: ALL` (Compose) |
| Privileges | `no-new-privileges:true` (Compose) |
| Writable paths | mounted `/data` volume + `/tmp` tmpfs only |
| Directory Manager | file mount only (`--directory-manager-password-file`); never env, never argv, never baked |
| Docker socket | never mounted |
| Secrets | prepared by the `native-secret-prep` one-shot into the `directory-secrets` volume as `0400` owned by 65532 (host secret files are `0600` and unreadable by the container uid directly) |
| Source / test trees | absent (build stage discarded; `.dockerignore` excludes secrets and tests) |

## Observed/target runtime contract (T-143 CLI)

| Item | Value |
| --- | --- |
| Entrypoint | `labldapd` (default `CMD`: `serve --help`) |
| Serve flags | `--config`, `--data-dir`, `--listen`, `--ldaps-listen`, `--tls-cert-file`, `--tls-key-file`, `--directory-manager-password-file`, `--health-listen` |
| Ports | `3389/tcp` LDAP, `3636/tcp` LDAPS (StartTLS on 3389), `8389/tcp` health |
| State | `/data/labldapd.bolt` (bbolt, mode 0600, owned by 65532) |
| Health | `GET http://127.0.0.1:8389/health` → 200 when serving; loopback-only, never published to the host |
| Listeners | bind `0.0.0.0` in-container so Compose peers reach them; host publishes stay `127.0.0.1` |

The health path `/health` follows the control-image convention. If T-143
ships a different health path, update the Dockerfile HEALTHCHECK and the
Compose healthcheck together.

## TLS

labldapd serves the **lab CA directory certificate directly**
(`secrets/tls/directory.crt` / `directory.key`, SAN `directory`): there is no
NSS database, no `dsctl tls import`, and no instance-CA publish step (that
machinery is 389-only). Bootstrap and control trust
`secrets/tls/ca.crt` (`LABLDAP_TLS_CA`), identical in ephemeral and
persistent native modes.

## Divergence from the 389 dirsrv contract

- No `DS_DM_PASSWORD` / `directory.env`; the engine reads the DM secret from
  a mounted file (ADR-0009 decision 13).
- No `dsconf` / `dsctl` / `dsidm` / LDAPI socket; the engine self-applies the
  compiled engine plan at start, and bootstrap reconcilers wait and read back
  over LDAP (ADR-0009 decisions 11–12).
- Ephemeral tmpfs `/data` is sized for bbolt (256Mi), not the 2GiB that
  389 DS first-boot requires; uid/gid are 65532, not 389.
- Health is an HTTP health listener, not the `container.inf` + LDAPI socket
  marker pair.

## Status dependencies

The image builds from `cmd/labldapd` as soon as that package compiles
(T-143 owns it). A live `make compose-up-native` additionally requires
T-143 (`labldapd serve`), T-144 (native bootstrap reconcilers), and T-146
(control engine wiring); until those merge, the Compose overlay is validated
statically (`docker compose ... config`) and must not be reported as a
passing bring-up.
