# Quick start

Stand up a disposable 389 DS lab, sign in to the UI, and make one change
you can see over REST, LDAP, and MCP.

## What you need

- Docker Engine **24+**
- Compose **v2.24+**
- A clone of this repository
- Ports **8443**, **3389**, and **3636** free on loopback

Go, Node, and pnpm are only required if you build from source. `make compose-up`
builds the images for you.

## 1. Start the lab

```bash
git clone https://github.com/hilather/go-lab-ldap-mcp.git
cd go-lab-ldap-mcp
make compose-up
```

This will:

1. Build `labldap-bootstrap:dev` and `labldap-control:dev`
2. Generate gitignored secrets under `secrets/`
3. Generate a lab CA and certificates
4. Start 389 DS (tmpfs-backed `/data` — ephemeral)
5. Run bootstrap against Directory Manager, then exit
6. Start the control plane

First run is image-build heavy. Later runs reuse the local images.

Persistent data instead of tmpfs:

```bash
make compose-up-persistent
```

## 2. Confirm it is up

```bash
curl -sk https://127.0.0.1:8443/health
curl -sk https://127.0.0.1:8443/health/ready
```

Both should return success. Ready waits for a working runtime bind, a matching
directory revision, and no reset in flight.

If ready never comes, see [Troubleshooting](../operations/troubleshooting.md).
`docker compose logs bootstrap` is the usual first look.

## 3. Open the UI

Browse to **https://127.0.0.1:8443/**.

The management certificate is a lab cert. Your browser will warn. Continue
anyway, or trust `secrets/tls/instance-ca.crt` (ephemeral) /
`secrets/tls/ca.crt` (persistent).

Sign in with the token in `secrets/token-admin`:

```bash
cat secrets/token-admin
```

That token is also the bearer for REST and HTTP MCP. Do not commit it.

The example scenario seeds user `alice` in group `staff` under
`dc=example,dc=test`. That seed is YAML — edit
[`deploy/compose/scenario.yaml`](../../deploy/compose/scenario.yaml) before
`make compose-up` to change it. See [Scenario YAML](scenario.md).

## 4. Call the API

```bash
TOKEN=$(tr -d '\n' < secrets/token-admin)

curl -sk -H "Authorization: Bearer $TOKEN" \
  https://127.0.0.1:8443/api/v1/users

curl -sk -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"id":"bob","password":"change-me-now"}' \
  https://127.0.0.1:8443/api/v1/users
```

OpenAPI: [`api/openapi.yaml`](../../api/openapi.yaml).

## 5. Bind as a directory user

From the host, with the lab CA:

```bash
ldapsearch -H ldap://127.0.0.1:3389 -ZZ \
  -x -D 'uid=alice,ou=people,dc=example,dc=test' \
  -y secrets/user-alice \
  -b 'dc=example,dc=test' '(uid=alice)'
```

Exact bind DNs follow the compiled scenario. The shipped suffix is
`dc=example,dc=test`. Check the UI user detail page or
`GET /api/v1/users/alice` if you changed it.

LDAPS is `ldaps://127.0.0.1:3636`. Trust the same lab CA. A wrong CA or
hostname fails closed.

## 6. Attach an MCP client

Local stdio (protocol on stdout, logs on stderr):

```bash
labldap mcp-stdio --config deploy/compose/scenario.yaml \
  --token-file secrets/token-admin
```

Or Streamable HTTP:

```http
POST /mcp
Authorization: Bearer <token-admin>
```

Read tools are on. Mutations stay off until the scenario sets
`spec.management.mcp.registerMutations` (and the other `register*` flags).

Catalog: [MCP catalog](../mcp/catalog.md).

## Stop, reset, start over

```bash
make compose-down          # stop containers
make compose-reset         # wipe volumes and start a fresh ephemeral lab
```

Soft reset (restore the compiled baseline, keep the volume) is the **Reset**
page in the UI, or `POST /api/v1/reset` with scope `lab:reset`.

## Next

- [User guide](user-guide.md) — every surface, every common job
- [Scenario YAML](scenario.md) — declare users, groups, ACLs, tokens
- [Deploy](deploy.md) — images, secrets, TLS, persistent mode
- [Operator guide](../operations/operator-guide.md) — limits and failure modes
