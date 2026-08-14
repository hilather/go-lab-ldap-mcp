# LDAP client compatibility matrix

Recorded: 2026-08-14  
Task: T-115  
Engine pin: see `deploy/docker/dirsrv.digest` and `deploy/docker/dirsrv-image-contract.md`.

LabLDAP does not implement the LDAP wire protocol. Compatibility is
**389 Directory Server 2.4.6** (pinned digest) plus the documented ACI
set applied by `labldap-bootstrap`.

## Ports

| Protocol | Host publish | Container |
| --- | --- | --- |
| LDAP | `127.0.0.1:3389` | 3389/tcp |
| LDAPS | `127.0.0.1:3636` | 3636/tcp |
| StartTLS | `127.0.0.1:3389` then StartTLS | 3389/tcp |

These are **not** 389/636. Upstream 389 DS container docs often show the
IANA ports; this pin listens on 3389/3636.

## Clients

| Client | Version recorded | Transports **exercised** | Notes |
| --- | --- | --- | --- |
| OpenLDAP `ldapsearch` | host `ldapsearch -VV` (test log; not committed) | **LDAPS**; paging on LDAPS | `-y` password-file. OpenLDAP 2.6 `-y` uses the complete file, including a trailing newline, so the test writes the password with no extra newline. |
| OpenLDAP `ldapwhoami` | same OpenLDAP package | **StartTLS** (`-ZZ` on 3389) | Alice bind. |
| OpenLDAP `ldapmodify` | same OpenLDAP package | **LDAPS** (host client) | DM `replace userPassword` (not RFC 3062; not alice self-service). CI installs `ldap-utils` and fails if `ldapmodify` is missing. |
| Independent Go (`go-ldap` v3.4.14) | `go.mod` | **LDAPS** and **StartTLS** | `test/compatibility/goindep`. Cleartext LDAP bind is expected to **fail** (`allowCleartextBind: false`). |
| Independent Python (`ldap3`) | venv at run time (not committed) | **LDAPS** and **StartTLS** | `test/compatibility/clients/python/client.py` with `--server-name localhost`. ldap3 matches `valid_names` to DNS SANs only and ignores IP SANs, so a connect host of `127.0.0.1` fails without the DNS name. Missing `python3` / `ldap3` fails in CI. |

The LabLDAP runtime pool (`internal/directory/ldapclient`) is **not** one
of the independent clients. It is covered by `test/integration/dirsrv/ldapclient_test.go`.

## ACI / identity behavior

Against a shipped apply (example suffix `dc=example,dc=test`):

| Actor | Search people/groups | Bind as self | Write own password (modify) | Write `cn=config` |
| --- | --- | --- | --- | --- |
| Directory Manager | yes | n/a | yes | yes (bootstrap only) |
| Seed user `alice` (staff read ACL) | yes (no `userPassword`) | yes | not asserted as self-service; DM replace is the matrix write | no (`cn=config` denied) |
| Anonymous | no (default `allowAnonymousBind: false`; asserted) | n/a | no | no |

Exact engine versions: `389-ds-base-2.4.6-1.fc39.x86_64`,
`389-Directory/2.4.6 B2024.212.0000` (T-024 contract).

## How to run

```text
make test-integration
# or the compatibility subset:
go test -tags=integration ./test/integration/dirsrv -run Compatibility -count=1 -timeout 30m
```

Host tools required in CI (installed by `.github/workflows/ci.yml`):
`/usr/bin/ldapsearch`, `/usr/bin/ldapwhoami`, `/usr/bin/ldapmodify`.
Locally those cases skip if the binary is missing. The Python client is
invoked with a throwaway venv; the repository does not vendor `ldap3`.
