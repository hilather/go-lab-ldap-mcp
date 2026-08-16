# ADR 0009: Native engine as a separate daemon with bbolt storage

## Status

Accepted

Date: 2026-08-15

Deciders: repository owner

Related tasks: T-122, T-124–T-146, T-150

Related ADRs: ADR-0008 (dual engines; this ADR is the native-side topology)

## Context

ADR-0008 selects a Go-native LDAP server as engine `native` but does not specify process shape, persistence, codec, or package layout. `AGENTS.md` requires an ADR before a layout that adds packages, and before changing bootstrap/runtime privilege boundaries.

Constraints that this ADR must preserve:

- Control plane is an LDAP client (ADR-0008 decision 3).
- Directory Manager is bootstrap-only; control never receives the DM secret.
- `/data` already has ephemeral (tmpfs) and persistent (named volume) meanings in compose.
- `github.com/go-asn1-ber/asn1-ber` is already a direct module dependency.
- Bootstrap today splits **engine ops** (`dsconf`: backend, TLS, pwpolicy, plugins) from **data ops** (LDAP as DM: tree, ACIs, seed, verify, marker).

## Decision

### Process topology

1. The native LDAP server is a **separate long-running process**: `cmd/labldapd` (`labldapd`).
2. Compose native mode keeps the three-role topology: **directory** (`labldapd`) → **bootstrap** (`labldap-bootstrap`) → **control** (`labldap`). LDAP clients continue to hit the directory listener, not the control plane.
3. **In-process embedding is allowed in tests only.** Production `labldap` / `labldap-bootstrap` binaries must not link `internal/ldapserver`. Integration tests under `test/parity` and `internal/ldapserver` may start an in-process listener on loopback.
4. `labldapd` binds LDAP / LDAPS / StartTLS per `spec.transport`. Default published host ports stay loopback `3389` / `3636`. Listeners default to loopback when address is unspecified.

### Storage

5. Directory contents persist in a **bbolt** single-file store under the engine data directory (compose: `/data/labldapd.bolt`, mode 0600, owned by the non-root runtime user).
6. Ephemeral vs persistent compose modes keep their meaning: tmpfs `/data` vs named volume. Soft reset is still suffix-scoped LDAP data rewrite, not file delete. Hard reset remains compose volume removal.
7. The store provides MVCC transactions so Search, Modify, and RFC 4528 assertion control share one snapshot/commit. An in-memory-only production store is rejected.
8. Indices required for Contract-tier search (equality on `uid`, `cn`, `member`, `uniqueMember`, `objectClass`, and DN) are internal to the store. There is no `dsconf index` apply path in native mode (`EnginePlan` has no indexes field today).

### Codec

9. BER encoding and decoding go through `github.com/go-asn1-ber/asn1-ber` behind an internal codec interface in `internal/ldapserver`. A from-scratch BER codec is rejected.
10. Pre-auth limits apply before bind: max PDU size, max outstanding operations per connection, read/write/idle deadlines, and abandon support. Values come from compiled `spec.limits` with conservative defaults.

### Bootstrap split

11. `labldapd` **self-applies the engine plan at start**: suffix existence, TLS materials, password-policy configuration, and plugin hooks (`memberof`, `referint`, `account-disable`). It does not shell out to `dsconf` / `dsctl` / `dsidm`.
12. `labldap-bootstrap` **keeps the data plane** (wait, tree, ACIs, seed, verify_runtime, verify_app, drift, marker) over LDAP as Directory Manager. Native implementations of `BackendReconciler`, `TLSReconciler`, `PolicyReconciler`, and `PluginReconciler` **wait and read back** rather than driving 389 CLI; they fail if the daemon’s applied engine plan does not match the compiled scenario.
13. Directory Manager for native mode is a configured root DN (default `cn=Directory Manager`) with a password file, same secret-injection rules as 389 mode. The native server enforces DM as the only identity that bypasses ACI.

### Package layout

```text
cmd/labldapd/                 # native directory daemon
internal/ldapserver/          # LDAPv3 listener, codec, dispatch, plugins, ACI eval
internal/ldapserver/store/    # bbolt Store implementation
internal/directory/native/    # bootstrap reconcilers + capability inspect for engine=native
test/parity/                  # dual-engine comparison harness
```

14. `internal/ldapserver` must not import `internal/api`, `internal/mcpserver`, `internal/web`, `internal/auth`, or `internal/directory/ds389`.
15. `internal/directory/ds389` must not import `internal/ldapserver`.
16. `internal/ldapserver` may import `internal/config` for already-pure DN, filter, and ACI-text helpers. It must not load YAML or connect as a client of itself.
17. `internal/directory/native` implements the bootstrap reconciler interfaces. Runtime repositories stay `ds389.Runtime` (LDAP against whichever engine is listening) unless a measured incompatibility forces a native runtime adapter — that would be a new ADR.

### Identity and schema 389-isms that native must carry

18. Account disable is the `nsAccountLock` attribute (bind result 53), not a private flag.
19. Lockout state is visible as `pwdAccountLockedTime` for bind-test parity.
20. MemberOf auto-adds the `nsmemberof` object class when the plugin is enabled.
21. The baseline marker remains `cn=labldap-baseline,<suffix>` with object class `device` and namespaced JSON in `description` (OD-012).

## Consequences

### Positive

- Compose, privilege matrix, and LDAP client instructions stay structurally identical across engines.
- Cloud agents can test W1–W5 in-process without Docker.
- bbolt maps onto existing `/data` volume semantics and is crash-safe enough for lab persistence.
- Reusing `asn1-ber` avoids a second BER implementation and a parallel fuzz surface.

### Negative

- Two directory images to pin (`dirsrv` digest and `labldapd`).
- Native bootstrap reconcilers are “verify the daemon did it,” which is a different failure vocabulary than `dsconf` apply; diagnostics must name the native phase.
- bbolt is not 389’s LMDB/BDB; performance and on-disk format are Deltas, not Contract.
- Embedding is test-only: a contributor who imports `ldapserver` from `cmd/labldap` is violating this ADR.

### Neutral / follow-up

- T-122 lands the interface skeletons on `main` before parallel implementation.
- T-123 adds `spec.directory.engine` (`389ds` | `native`) without a new `apiVersion`. The omitted-field default became `native` in the ADR-0008 amendment of 2026-08-16.
- T-143–T-146 ship `labldapd`, native reconcilers, image, and `make compose-up-native`.
- Pin the bbolt module version at first import (T-129). Record the version in the parity contract’s implementation notes.

## Alternatives considered

| Option | Why not chosen |
| --- | --- |
| Embed `ldapserver` in the control process | Violates ADR-0008 decision 3; mixes management and directory listeners; DM secret risk. |
| In-memory store plus optional WAL | Ephemeral labs still need crash-consistent restart inside a tmpfs-backed `/data`; WAL design is extra invention. bbolt covers both modes. |
| From-scratch BER codec | No product value; `asn1-ber` is already required by `go-ldap`. |
| Drive native engine config through `dsconf`-shaped CLI | Fake compatibility with a tool that will not exist. Self-apply + LDAP read-back is the native admin plane (parity Delta). |
| Separate native runtime repository package in v1 | `ds389.Runtime` is already LDAP-portable (standard OCs, `member`/`memberOf`, paging, assertion). Forking it before measuring a gap doubles M3. |

## Notes

- Accepted ADRs outrank other repository documents.
- Native `labldapd` runs as non-root with a read-only root filesystem in release compose, matching control-image hardening where the listener and `/data` allow it.
- Do not add a native-engine REST admin API in M9. Engine configuration enters through the scenario file and daemon flags/files, same secret-file rules as today.
