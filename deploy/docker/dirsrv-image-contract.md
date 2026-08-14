# 389 Directory Server image contract

Recorded: 2026-08-12  
Decision: OD-006 / T-024

## Pin

| Field | Value |
| --- | --- |
| Reference | `quay.io/389ds/dirsrv@sha256:f2851654c5df545cd893d84bea8d08c28dc25f0930493fbfed1d8a6eacf657f7` |
| Discovery tag (not for release files) | `quay.io/389ds/dirsrv:latest` pulled 2026-08-12 |
| Architecture observed | digest is a multi-arch list (`linux/amd64`, `linux/arm64`, `linux/ppc64le`, `linux/s390x`). **Advertised:** `linux/amd64` only (T-116). |
| Package | `389-ds-base-2.4.6-1.fc39.x86_64` |
| ns-slapd | `389-Directory/2.4.6 B2024.212.0000` |
| Label `version` | `39` (Fedora 39 container) |

The immutable digest is also in `deploy/docker/dirsrv.digest`. Harness code must read that file. Do **not** put a floating `quay.io/389ds/dirsrv:<tag>` in Compose, Dockerfiles, or Makefile release paths.

T-041 copies a static `labldap-bootstrap` onto this image (`labldap-bootstrap:dev`). `/etc/dirsrv/slapd-localhost` is a symlink to `/data/config`. A separate bootstrap container may mount `/data` **read-only** for the instance CA (`/data/config/ca.crt`) and the LDAPI socket used by `dsconf localhost`.

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

## TLS import (observed)

**Do not** bind-mount PEMs or `pwdfile.txt` on first boot: NSS `reinit()` fails with `Device or resource busy`, and a later copy+restart leaves LDAPS looking for a missing `Server-Cert`.

After first-boot writes `/data/config/container.inf`, import works. `/data` must be a Docker volume so restart does not look like an empty tree.

```text
dsctl localhost tls import-ca /path/ca.crt LabLDAP-Test-CA
dsctl localhost tls import-server-key-cert /path/server.crt /path/server.key
docker restart   # ns-slapd must reload NSS; then re-read published ports
```

`dsctl tls` is the supported wrapper around `certutil` / `pk12util`. Integration LDAPS tests use this path and trust the **generated test CA**, not the instance self-signed CA.

## Divergence from generic “LDAP on 389/636” docs

Upstream docs often show 389/636. This container listens on **3389/3636**. Health is not a Docker HEALTHCHECK; readiness is LDAPI socket `/data/run/slapd-localhost.socket` plus TCP accept on 3389.

## Bind policy (observed, T-030)

Default first-boot: `nsslapd-require-secure-binds: off`, `nsslapd-allow-anonymous-access: on`. LDAPS (3636) and StartTLS on 3389 both accept binds. After `dsconf security set --require-secure-authentication on`, a simple bind on `ldap://:3389` returns LDAP 13 (confidentiality required). SASL `get-mechs` includes EXTERNAL, GSSAPI, DIGEST-MD5, PLAIN, ANONYMOUS; there is no scenario YAML key for required SASL — `phase.tls` fails `sasl_missing` when `TLSRequest.RequiredSASL` names a mechanism not in that list.

## Password policy (observed, T-031)

`dsconf pwpolicy set/get` maps: `--pwdminlen` (2–512 only; 0/1 invalid), `--pwdhistory`/`--pwdhistorycount`, `--pwdexpire`/`--pwdmaxage` (maxage 0 invalid — disable via expire off), `--pwdwarning`, `--pwdlockout`/`--pwdmaxfailures`/`--pwdlockoutduration`, `--pwdscheme`. Canonical `PBKDF2-SHA256` is a native scheme. Compiled `minLength` outside 0 and 2–512 is `unsupported_field`. `minLength: 0` is left unset (does not clear a prior minimum). Applying `minLength` ≥ 2 turns `--pwdchecksyntax` on and sets `--pwdmincatagories 1` (range 1–5), `--pwdmintokenlen 64` (range 1–64; 0 is invalid, so 64 minimizes trivial-word matching), `--pwddictcheck off`, `--pwdpalindrome off` so the compiled minimum is the effective extra constraint.

## Plugins (observed, T-032)

Default first-boot: MemberOf and referential integrity are **off**. `dsctl` has no restart. Enabling them without a restart requires `dsconf config replace nsslapd-dynamic-plugins=on` **before** `plugin … enable`. `plugin memberof show -j` emits LDIF; use `plugin show "MemberOf Plugin"` / `plugin show "referential integrity postoperation"` for JSON.

| Compiled name | Apply | Read-back |
| --- | --- | --- |
| `memberof` | enable; `set --attr memberOf --groupattr member --scope <suffix> --autoaddoc nsmemberof`; `fixup --wait <suffix>` | enabled on, `memberOf`/`member`, scope = suffix |
| `referint` | enable; `set --update-delay 0 --membership-attr member --entry-scope/--container-scope <suffix>` | enabled on, watches `member` |
| `account-disable` | not a dsconf plugin — `schema attributetypes query nsAccountLock` | attribute `nsAccountLock` present; bind with `nsAccountLock: true` returns LDAP 53, entry remains |

Unknown compiled plugin names are `plugin_missing`. Failed MemberOf fix-up is `fixup_failed`. A second `plugin … set` with the same values exits 1 (`nothing to set`); apply treats that as success.

## Base tree (observed, T-033)

`dsconf backend create --create-suffix` creates the suffix root as `objectClass: top, domain` with no children. Re-adding an existing entry returns LDAP 68. People/groups containers are `organizationalUnit`. The runtime account is `inetOrgPerson` under `ou=people` (`uid=<id>,ou=people,<suffix>`). It is not placed in any group.

## ACIs (observed, T-034)

`--create-suffix` installs an unmanaged `Enable anyone domain read` ACI on the suffix root. LabLDAP owns only `aci` values whose `acl "..."` name starts with `labldap:`. Adding an identical value again returns LDAP 20. A malformed ACI returns LDAP 21 (`ACL Syntax Error`). Read-back is compared after collapsing whitespace.

`targetattr!="aci"` on `labldap:runtime-people-write` / `labldap:runtime-groups-write` (KD-R23) is accepted by 2.4.6 and denies runtime ACI rewrite (LDAP 50). Runtime people-write still grants read of hashed `userPassword` on people entries; suffix-read deny is `targetattr!="userPassword"` on the suffix/marker. `nsAccountLock: true` bind is LDAP 53. Password lockout is confirmed when the correct password also fails after `pwdmaxfailures`.

## Baseline marker attributes (OD-012, T-039)

Observed on the pinned 2.4.6 image: `objectClass: top, device` with `cn` is accepted. Adding the preferred KD-R17 set (`serialNumber`, `owner` as `labldap-bootstrap/<version>`, `description` as RFC3339, `destinationIndicator` as the Directory revision hex) is rejected (objectClass / syntax). Bootstrap therefore writes **namespaced `description` JSON only**:

```json
{"serialNumber":"<hex>","destinationIndicator":"<hex>","owner":"labldap-bootstrap/<version>","appliedAt":"<RFC3339>"}
```

No secret digests. Private OID registration remains an owner checkpoint before stable release, not a T-039 blocker. Runtime may read the marker and must not modify it.

## Environment (subset)

- `DS_DM_PASSWORD` — set Directory Manager password after first start
- `DS_SUFFIX_NAME` — optional default suffix (`SUFFIX_NAME` deprecated)
- `DS_STARTUP_TIMEOUT` — seconds (default 60)
- `DS_ERRORLOG_LEVEL` — ns-slapd error log level
