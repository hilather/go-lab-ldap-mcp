# ADR 0010: Configurable management HTTP Host allow-list

## Status

Accepted

Date: 2026-08-19

Deciders: repository owner

Related tasks: GitHub issue #3

Related ADRs: none

## Context

The management HTTP stack (REST, MCP Streamable HTTP, and the embedded UI)
rejects `Host` headers that are not on a compiled allow-list. For loopback
and bind-all listens (`127.0.0.1`, `localhost`, `::1`, `0.0.0.0`, `::`)
`auth.LoopbackHosts` accepts only exact `host:port` values on the *listen*
port (`127.0.0.1:8443`, `localhost:8443`, `[::1]:8443`, `control:8443`).

Compose commonly binds `0.0.0.0:8443` inside the container and publishes a
different host port. Operators also reach the UI by LAN or public IP.
Those requests arrive as `Host: localhost:9443` or `Host: 10.165.0.199:9443`
and receive `400 host is not allowed`, while `Host: control:8443` succeeds.

An empty `HostAllowed` list still means “allow any Host”. The runtime must
not pass an empty list when `LoopbackHosts` produced defaults; that would
silently disable DNS-rebinding protection.

`docs/13-open-decisions.md` §5 requires an ADR before changing public
configuration semantics.

## Decision

1. Add optional `spec.management.allowedHosts` on `labldap.dev/v1alpha1`.
   Same `apiVersion`. Omitted or empty extras keep today’s `LoopbackHosts`
   (and the bind-all published-port loopback hostnames below).
2. Extra hosts are a **union** on top of `LoopbackHosts`, never a replacement.
   Additional sources: `LABLDAP_MANAGEMENT_ALLOWED_HOSTS` (comma-separated)
   and repeatable `--management-allowed-host`. YAML, env, and CLI are
   compiled together in `internal/config` (no LDAP I/O).
3. Matching:
   - Default `LoopbackHosts` entries stay exact case-insensitive `Host`
     (`host:port`) matches.
   - Extra `host:port` is an exact case-insensitive match on `Request.Host`.
   - Extra `host` (no port) matches the hostname of `Request.Host` on any
     port, including IPv6 in bracket form.
4. When listen is loopback or bind-all, the runtime also unions host-only
   `127.0.0.1`, `localhost`, `::1`, and `control`. That accepts published-port
   `Host: localhost:9443` without listing every mapping. It does **not**
   accept arbitrary hostnames (`evil.test` stays rejected).
5. Reject empty strings, `*`, URLs with a scheme or path, and other junk at
   compile/validate time with a field error. Never treat extras as “allow
   all”. Wildcard credentialed CORS remains impossible; this ADR does not
   add a raw host-allow REST/MCP API.
6. **Amendment 2026-08-20:** a `Request.Host` whose name is a literal IPv4
   or IPv6 address (with or without a port, including bracketed IPv6) is
   accepted even when it is not listed. DNS rebinding presents a hostname
   (`Host: evil.test`), not an IP. Extra hostnames remain required for
   non-loopback DNS names. `*` stays rejected.

## Consequences

### Positive

- Server-hosted labs can allow a public IP or published hostname without
  a reverse-proxy Host rewrite.
- Secure default is unchanged for unlisted hosts.
- One matcher is shared by REST and MCP.

### Negative

- Host-only extras widen the allowed port set for that hostname. Operators
  must not list names they do not control.
- Bind-all/loopback now accepts loopback hostnames on any port. That is
  broader than exact listen-port matching but still not an open Host list.

### Neutral / follow-up

- Schema, examples, and compatibility notes land with this change.
- Control and directory revision hashes are unchanged (optional field,
  omitted default).

## Alternatives considered

| Option | Why not chosen |
| --- | --- |
| Replace `LoopbackHosts` with the YAML list | Empty extras would become “allow all” or would reject `control:8443`. |
| Silently allow any Host when listen is `0.0.0.0` | Re-opens DNS rebinding (`Host: evil.test`). Literal IP Host headers are accepted (amendment 2026-08-20) because they are not a rebinding hostname. |
| Accept `*` | Same as allow-all; rejected at compile time. |
| New `apiVersion` | Backward-compatible optional field; no break. |

## Notes

- Security defaults may become stricter in a minor release; insecure
  behavior must never become the silent default.
