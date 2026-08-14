# LabLDAP operator guide

This is the first-usable-release operator package (T-119). Deploy from
these files plus the Make targets. Bootstrap (`labldap-bootstrap apply`)
is the only supported engine configuration path. Do not run extra
directory-engine CLI by hand.

Working names (OD-001): LabLDAP, `labldap`, `labldap-bootstrap`.
Local images only (OD-004). No distribution LICENSE file (OD-003).

## What you get

| Surface | How to reach it |
| --- | --- |
| REST | `https://127.0.0.1:8443/api/v1` (OpenAPI: `api/openapi.yaml`) |
| Embedded UI | `https://127.0.0.1:8443/` |
| Direct LDAP | `ldap://127.0.0.1:3389` and `ldaps://127.0.0.1:3636` |
| MCP | `POST /mcp` (bearer) and `labldap mcp-stdio`. Read tools on by default; mutations off until `register*`. Catalog: [docs/mcp/catalog.md](https://github.com/hilather/go-lab-ldap-mcp/blob/main/docs/mcp/catalog.md). |

389 Directory Server is the directory engine. The Go service does **not**
implement the LDAP wire protocol.

## Limitations (read first)

- **Not Active Directory.** There is no NTLM, Kerberos, GPOs, `sAMAccountName`
  uniqueness model, SID history, or AD-style schema. Clients that assume
  Active Directory will not work. LabLDAP is generic LDAPv3 against 389 DS.
- **Ephemeral tmpfs is not a forensic wipe.** Host swap can still persist
  tmpfs pages (non-negotiable 7).
- **One suffix, one 389 DS instance, one control replica.** Not HA.
- **Hard engine reset is not an API.** `make compose-reset` (volume removal)
  is operator-only. REST/MCP expose suffix-scoped soft reset only.
- **Directory Manager never goes to control.** DM is bootstrap-only.
- **Advertised architecture is `linux/amd64` only.** See
  [architectures.md](https://github.com/hilather/go-lab-ldap-mcp/blob/main/deploy/docker/architectures.md).
- **Host checks:** Compose listens on `0.0.0.0:8443` inside the container
  but still allow-lists `127.0.0.1` / `localhost` / `control` (loopback
  publish). A spoofed `Host: evil.test` is rejected.

## Prerequisites

- Docker Engine **24+** and Compose **v2.24+** (OD-020). `make compose-up`
  runs `tools/composepreflight`.
- Go 1.26 / toolchain `go1.26.5` if you build from source (`docs/toolchain.md`).
- Secret files are untracked (`/secrets/`). Examples under
  `config/examples/secrets/` are **lab placeholders** (`lab-fixture-*`),
  not production credentials.

## Packaged artifacts

| Path | Role |
| --- | --- |
| `deploy/compose/compose.yaml` | Base topology (pinned 389 DS digest) |
| `deploy/compose/compose.ephemeral.yaml` | Default: tmpfs-backed `/data` |
| `deploy/compose/compose.persistent.yaml` | Named volume |
| `deploy/compose/scenario.yaml` | Ephemeral lab scenario |
| `deploy/compose/scenario.persistent.yaml` | Persistent lab scenario |
| `config/examples/example-lab.yaml` | Compiler example |
| `config/schema/v1alpha1.json` | JSON Schema |
| `api/openapi.yaml` | REST contract |
| `docs/compatibility/ldap-clients.md` | LDAP client matrix |
| `docs/operations/limits.md` | Measured limits |

## Deploy (ephemeral, default)

From a clean checkout:

```text
make compose-up
```

That builds `labldap-control:dev` and `labldap-bootstrap:dev`, generates
gitignored secrets and a lab CA, starts 389 DS, publishes the **instance
CA** to `secrets/tls/instance-ca.crt`, runs bootstrap `apply`, then starts
control.

Host publishes (loopback only):

- `127.0.0.1:8443` management (self-signed; `wget --no-check-certificate https://127.0.0.1:8443/health`)
- `127.0.0.1:3389` LDAP
- `127.0.0.1:3636` LDAPS

Probe liveness with `GET /health`. Readiness is `GET /health/ready`.

Stop: `make compose-down`. Operator hard reset: `make compose-reset`
(`down -v`, then `compose-up`).

## Deploy (persistent)

```text
make compose-up-persistent
```

Uses a named volume for `/data`. After first boot the helper runs the
**documented** TLS import:

```text
dsctl localhost tls import-ca …
dsctl localhost tls import-server-key-cert …
```

That is the only directory-engine CLI path operators need. Do not hand-edit
`cn=config`. Restart keeps runtime entries. Soft reset
(`POST /api/v1/reset` with `lab:reset`, scenario name, and expected
revision) restores the compiled baseline without removing the volume.

## Secrets and TLS

```text
go run ./tools/setupsecrets --dir secrets
go run ./tools/setupsecrets --dir secrets --force    # rotate
go run ./tools/setuptls generate --dir secrets/tls --host directory
```

Existing files are not overwritten unless `--force`. Mode 0600 on the host.
Control reads token and runtime passwords from a prepared volume (uid
65532, mode 0400). The private CA key stays on the host and is **not**
mounted into runtime services.

## REST, UI, and LDAP

- Bearer token from `secrets/token-admin` for REST.
- Browser: open `https://127.0.0.1:8443/`, exchange the token for a session
  cookie. Tokens are not stored in `localStorage`.
- LDAP clients: see
  [ldap-clients.md](https://github.com/hilather/go-lab-ldap-mcp/blob/main/docs/compatibility/ldap-clients.md).
  Ports are **3389/3636**, not 389/636.

## Export and reset

- Soft reset: UI Reset page or `POST /api/v1/reset` (scope `lab:reset`).
- LDIF export: `GET /api/v1/export` (scope `lab:export`). Passwords omitted
  by default. Bounded by compiled `exportMaxEntries` / `exportMaxBytes`.
- Hard reset: `make compose-reset` only.

## Security defaults

Control: non-root `65532`, read-only root, `cap_drop: ALL`,
`no-new-privileges`, no Docker socket, no Directory Manager.
Wildcard credentialed CORS is impossible. `insecureLabMode` logs a
startup warning and is off in shipped examples.

SBOM / scan / checksums: `make sbom`, `make scan`, `make checksums`.
Critical findings fail `make verify` / `make test-security`.

## Troubleshooting

See [troubleshooting.md](https://github.com/hilather/go-lab-ldap-mcp/blob/main/docs/operations/troubleshooting.md).
