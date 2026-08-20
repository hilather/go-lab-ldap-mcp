# Scenario YAML

Users, groups, ACLs, tokens, and lab policy are declared in a
`labldap.dev/v1alpha1` **LabScenario** file. Bootstrap compiles that file
and writes real directory entries in the selected engine. The YAML is the
lab definition — not an in-memory directory.

Shipped examples:

- [`deploy/compose/scenario.yaml`](../../deploy/compose/scenario.yaml) — default Compose lab
- [`deploy/compose/scenario.persistent.yaml`](../../deploy/compose/scenario.persistent.yaml) — same tree, `storageMode: persistent`
- [`config/examples/example-lab.yaml`](../../config/examples/example-lab.yaml) — commented host-path example
- Schema: [`config/schema/v1alpha1.json`](../../config/schema/v1alpha1.json)

## Directory engine

`spec.directory.engine` selects the directory engine (ADR-0008):

| Value | Meaning |
| --- | --- |
| `native` | In-repo Go engine (`labldapd`). **Default** when the field is omitted (v0.3.0). |
| `389ds` | Pinned 389 Directory Server container. Oracle and rollback. |

The field is optional. Omitting it now selects `native`. Add `engine: 389ds`
before upgrading if you must keep 389 DS. Engine is part of the compiled
plan (`labldap plan` output) and the directory revision, so switching
engines is a re-bootstrap / hard reset, not a live change. See
[`docs/design/native-engine-parity-contract.md`](../design/native-engine-parity-contract.md).

## Additional managed suffixes

`spec.directory.suffix` stays the primary naming context. People,
groups, the runtime account, and the baseline marker live under it.

Optional `spec.directory.additionalSuffixes` adds sibling naming
contexts in the same lab (ADR-0011). Values must be valid DNs, distinct
from the primary, and not nested inside the primary or each other.
Omitted or empty keeps today's single-suffix lab. This is **not** an AD
forest or a cross-domain trust.

```yaml
spec:
  directory:
    suffix: "dc=example,dc=test"
    additionalSuffixes:
      - "dc=region1,dc=example,dc=net"
      - "dc=region2,dc=example,dc=net"
```

Bootstrap creates each extra suffix (389: a separate `labldapN` backend
with `--create-suffix`; native: extra naming contexts). Runtime writes
and search bases must stay under the compiled managed set. Extra OU
trees and exact-DN service users are created through REST / MCP / the
Tree console page (`ldap_create_entry`, `dn` / `parentDN` on user and
group create) — scenario YAML users and groups still compile under
`peopleRDN` / `groupsRDN` on the primary suffix.

See [ADR-0011](../adr/0011-multi-domain-managed-suffixes-and-structured-entries.md).

## Declare users and groups

```yaml
apiVersion: labldap.dev/v1alpha1
kind: LabScenario
metadata:
  name: compose-lab
spec:
  directory:
    suffix: "dc=example,dc=test"
    peopleRDN: "ou=people"
    groupsRDN: "ou=groups"
    nestedGroups: false

  users:
    - id: alice
      uid: alice
      passwordFile: /run/secrets/user-alice
      enabled: true
      attributes:
        givenName: Alice
        sn: Anderson
        mail: alice@example.test

    - id: bob
      uid: bob
      passwordFile: /run/secrets/user-bob
      enabled: true

  groups:
    - id: staff
      members:
        - user: alice
        - user: bob
    - id: admins
      members:
        - user: alice
```

What that becomes on the wire:

| YAML | Directory |
| --- | --- |
| `users[].id` / `uid` | `uid=<id>,ou=people,<suffix>` |
| `passwordFile` | `userPassword` (hashed by the engine, `PBKDF2-SHA256` in the example) |
| `enabled: false` | `nsAccountLock` |
| `attributes` | extra string attrs (`givenName`, `sn`, `mail`, …) |
| `groups[].id` | `cn=<id>,ou=groups,<suffix>` (`groupOfNames`) |
| `members.user` | `member: uid=…` |

Optional per user: `rdn` or `dn` if you need a non-default naming attribute.
`uid` defaults to `id`.

The same file also holds the runtime service account, password policy,
ACLs, and control-plane tokens. See the shipped scenario for a complete
lab.

## Management HTTP Host allow-list

The control plane rejects `Host` headers that are not on a compiled
allow-list (DNS-rebinding protection). Loopback and bind-all listens
(`127.0.0.1`, `localhost`, `0.0.0.0`, `::`) already accept exact
`host:port` values on the listen port (`control:8443`, `localhost:8443`,
…) plus host-only `localhost` / `127.0.0.1` / `::1` / `control` so a
published port such as `localhost:9443` works without extra config.

Literal IP Host headers are accepted without extras. To allow an extra
**hostname**, add extras. They **union** with the defaults; they do not
replace them. `*` is rejected.

```yaml
spec:
  management:
    listen: "0.0.0.0:8443"
    allowedHosts:
      - "10.165.0.199"      # any port (published 9443, …)
      - "lab.example.com"
      - "localhost:9443"    # exact Host only
```

Equivalent sources (also unioned):

- `LABLDAP_MANAGEMENT_ALLOWED_HOSTS=10.165.0.199,lab.example.com`
- `labldap serve --config scenario.yaml --management-allowed-host 10.165.0.199`

Unlisted hostnames such as `evil.test` stay `400 host is not allowed`.
See [ADR-0010](../adr/0010-management-http-allowed-hosts.md).

## Rules

- **No inline passwords.** Every user (and the runtime account, and every
  token) points at a `passwordFile` / `secretFile`. `make compose-up`
  writes those files under `secrets/` (mode 0600, gitignored).
- **Groups cannot be empty.** 389 `groupOfNames` requires at least one
  `member`. Nested groups stay off unless `nestedGroups: true`; then a
  member may be `{ group: other }`.
- **YAML is the compiled baseline**, not a live sync loop.
  `startupMode: merge` (the default) applies it at bootstrap. The UI,
  REST, and MCP can add more users later. Soft reset restores this file.
  Soft reset does not wipe the Docker volume.
- **Changing the file means re-bootstrap.** Edit
  `deploy/compose/scenario.yaml` (or point `LABLDAP_SCENARIO_FILE` at
  another path), then `make compose-up` / `compose-up-persistent`. The
  running control plane does not remount a new scenario on the fly.
- **`allowRawACI: false`.** Declare `acls:` in YAML. Do not paste 389 ACI
  text into the scenario.

## ACLs in the same file

```yaml
  acls:
    - id: staff-read
      principal:
        kind: group
        ref: staff
      target:
        kind: suffix
      permissions: [read, search, compare]
      attributes:
        allow: ["*"]
        deny: [userPassword]
```

That compiles to 389 ACIs on the suffix. Seed user `alice` can search
people and groups, bind as herself, and cannot read `userPassword` or
write `cn=config`.

## Apply it

1. Put secret files next to the scenario (Compose mounts
   `/run/secrets/…` from `secrets/` on the host).
2. `make compose-up` (ephemeral) or `make compose-up-persistent`.
3. Bind as a seeded user, not as Directory Manager:

```bash
ldapsearch -H ldap://127.0.0.1:3389 -ZZ \
  -x -D 'uid=alice,ou=people,dc=example,dc=test' \
  -y secrets/user-alice \
  -b 'dc=example,dc=test' '(uid=alice)'
```

Exact DNs follow `spec.directory.suffix`. The example suffix is
`dc=example,dc=test`.

## Baseline vs runtime

| Path | What happens |
| --- | --- |
| Scenario YAML | Compiled once at bootstrap. Soft reset target. |
| UI / REST / MCP | Live mutations on the selected engine. Survive until reset or volume wipe. |
| `make compose-reset` | Destroy the volume, apply the YAML again. |

Next: [User guide](user-guide.md) · [Quick start](quickstart.md) · [Deploy](deploy.md)
