# 389 Directory Server image contract

Recorded: 2026-08-12  
Decision: OD-006 / T-024

## Pin

| Field | Value |
| --- | --- |
| Reference | `quay.io/389ds/dirsrv@sha256:f2851654c5df545cd893d84bea8d08c28dc25f0930493fbfed1d8a6eacf657f7` |
| Discovery tag (not for release files) | `quay.io/389ds/dirsrv:latest` pulled 2026-08-12 |
| Architecture observed | `linux/amd64` |
| Package | `389-ds-base-2.4.6-1.fc39.x86_64` |
| ns-slapd | `389-Directory/2.4.6 B2024.212.0000` |
| Label `version` | `39` (Fedora 39 container) |

The immutable digest is also in `deploy/docker/dirsrv.digest`. Harness code must read that file. Do **not** put a floating `quay.io/389ds/dirsrv:<tag>` in Compose, Dockerfiles, or Makefile release paths.

## Observed runtime contract

| Item | Observation |
| --- | --- |
| Cmd | `/usr/libexec/dirsrv/dscontainer -r` |
| Entrypoint | none |
| User | image `User` empty (process starts as root); `dirsrv` uid/gid **389** exists |
| Ports | **3389/tcp** LDAP, **3636/tcp** LDAPS (container-internal; not 389/636) |
| State | `/data` (`config`, `ssca`, `db`, `bak`, `ldif`, `run`, `logs`) |
| Marker | `/data/config/container.inf` |
| CLI | `dsconf`, `dsctl`, `dsidm`, `ldapsearch`, `ns-slapd` |
| `dsconf` | supports `-y PWDFILE` (password file) |

## Secrets (OD-007)

The image **does not** implement `DS_DM_PASSWORD_FILE`. Directory Manager password is accepted only via **`DS_DM_PASSWORD`**. A thin file-to-env wrapper is deferred to T-027 if still required. Tests must not log the password and must redact it from captured `docker logs`.

## TLS PEM import (observed)

If all of the following exist at start, `dscontainer` loads them into the NSS DB.

**Observed:**
- Bind-mounting `/data/config/pwdfile.txt` on an empty `/data` makes first-time NSS `reinit()` fail (`Device or resource busy`).
- Copying PEMs after the marker exists and restarting still leaves LDAPS disabled (`Can't find certificate (Server-Cert)`). Integration LDAPS tests therefore trust the **instance self-signed CA** extracted from `/etc/dirsrv/slapd-localhost/ca.crt`. The generated SAN helper remains for fixtures (wrong-CA) and a unit test.

If all of the following exist at start (after the instance marker exists), `dscontainer` loads them into the NSS DB:

| Path | Role |
| --- | --- |
| `/data/tls/server.key` | server private key |
| `/data/tls/server.crt` | server certificate |
| `/data/tls/ca/*.crt` | CA certs |
| `/data/config/pwdfile.txt` | NSS PIN file |

## Divergence from generic “LDAP on 389/636” docs

Upstream docs often show 389/636. This container listens on **3389/3636**. Health is not a Docker HEALTHCHECK; readiness is LDAPI socket `/data/run/slapd-localhost.socket` plus TCP accept on 3389.

## Environment (subset)

- `DS_DM_PASSWORD` — set Directory Manager password after first start
- `DS_SUFFIX_NAME` — optional default suffix (`SUFFIX_NAME` deprecated)
- `DS_STARTUP_TIMEOUT` — seconds (default 60)
- `DS_ERRORLOG_LEVEL` — ns-slapd error log level
