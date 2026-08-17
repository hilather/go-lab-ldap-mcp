# Troubleshooting

Work top-down. Do not invent extra engine-CLI steps. The only supported
engine configuration path is `labldap-bootstrap apply` plus the TLS
import documented in the
[operator guide](https://github.com/hilather/go-lab-ldap-mcp/blob/main/docs/operations/operator-guide.md).

## Control never becomes ready

1. `GET https://127.0.0.1:8443/health` must be 200 even if LDAP is down.
2. `GET /health/ready` requires a successful runtime bind, marker, matching
   directory revision, capabilities, and no active reset.
3. `GET /api/v1/diagnostics` (authenticated) shows component status. It
   must not include secret values or secret file contents.
4. If bootstrap exited non-zero, control will not start
   (`depends_on: service_completed_successfully`). `docker compose logs bootstrap`.

## Bootstrap failed

Typical causes:

- Invalid scenario YAML (unknown fields, missing secrets).
- Directory not healthy (native: health listener; 389: `/data/config/container.inf` missing).
- Wrong CA / SAN: TLS verify fails closed.
- DM password file missing or empty.
- Native daemon pointed at a 389 `/data` tree (`engine_data_mismatch`).
  Run `compose-reset` or set `engine: 389ds`.

Fix the scenario or secrets, then `make compose-up` again. Do not pass
`--directory-manager-password` on the command line.

## LDAPS / StartTLS fails from the host

- Ports are **3636** (LDAPS) and **3389** (LDAP / StartTLS).
- Default native stack: trust `secrets/tls/ca.crt`.
- 389 rollback ephemeral: trust `secrets/tls/instance-ca.crt`.
- 389 rollback persistent: trust `secrets/tls/ca.crt` after `setuptls import`.
- A wrong CA or hostname fails closed. That is required, not a bug.

## Runtime entries vanished (ephemeral)

Ephemeral `/data` is tmpfs-backed. Container recreate that remounts the
volume object starts empty; bootstrap reapplies the baseline. This is
expected. Host swap can still hold pages — ephemeral is not a wipe.

## Persistent restart dropped a published port

`docker compose restart directory` can drop published ports. Run
`docker compose up -d --wait directory` then wait for control
`/health/ready`. Soft reset does **not** remove the volume.

## Token or session rejected

- REST: `Authorization: Bearer` with the token file value. 401 does not
  include token IDs.
- Browser: cookie + `X-CSRF-Token` + same-origin. Cross-origin preflight
  is 403 unless the origin is allow-listed.
- Host header on a loopback listen (`127.0.0.1:8443`) must be loopback.

## Image version mismatch

`make image` compares `labldap-control:dev` and `labldap-bootstrap:dev`
`version=` fields. Rebuild both with the same `VERSION`.

## Need a clean lab

```text
make compose-reset
```

That is the operator hard reset. It is not exposed over REST or MCP.
