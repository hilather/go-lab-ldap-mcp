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

| Client | Version recorded | Transports | Notes |
| --- | --- | --- | --- |
| OpenLDAP `ldapsearch` / `ldapwhoami` | host `ldapsearch -VV` (see test log) | LDAP, LDAPS (`-H ldaps://…`), StartTLS (`-ZZ`) | Paging: `-E pr=2/noprompt`. Password modify: `ldapmodify` replace `userPassword`. |
| Independent Go (`github.com/go-ldap/ldap/v3`) | `v3.4.14` (`go.mod`) | LDAP, LDAPS, StartTLS | `test/compatibility/goindep`. Paging via `SearchWithPaging`. Password via modify replace. |
| Independent Python (`ldap3`) | installed in the test venv at run time | LDAP, LDAPS, StartTLS | `test/compatibility/clients/python/client.py`. Skips if `pip` cannot install `ldap3`. |

The LabLDAP runtime pool (`internal/directory/ldapclient`) is **not** one
of the independent clients. It is covered by `test/integration/dirsrv/ldapclient_test.go`.

## ACI / identity behavior

Against a shipped apply (example suffix `dc=example,dc=test`):

| Actor | Search people/groups | Bind as self | Write own password (modify) | Write `cn=config` |
| --- | --- | --- | --- | --- |
| Directory Manager | yes | n/a | yes | yes (bootstrap only) |
| Seed user `alice` (staff read ACL) | yes (no `userPassword`) | yes | engine-dependent | no |
| Anonymous | no (default `allowAnonymousBind: false`) | n/a | no | no |

Exact engine versions: `389-ds-base-2.4.6-1.fc39.x86_64`,
`389-Directory/2.4.6 B2024.212.0000` (T-024 contract).

## How to run

```text
make test-integration
# or the compatibility subset:
go test -tags=integration ./test/integration/dirsrv -run Compatibility -count=1 -timeout 25m
```

Host tools used when present: `/usr/bin/ldapsearch`, `/usr/bin/ldapwhoami`.
The Python client is invoked with a throwaway venv; the repository does
not vendor `ldap3`.
