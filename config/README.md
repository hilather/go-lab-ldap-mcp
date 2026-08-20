# Configuration

Human guide: **[docs/guides/scenario.md](../docs/guides/scenario.md)**.
Users, groups, ACLs, and tokens are declared in a `labldap.dev/v1alpha1`
LabScenario YAML. Passwords are file references, never inline.

JSON Schema, examples, and the `v1alpha1` stand-in live here.
`internal/config` must not connect to LDAP.

`spec.management.allowedHosts` is optional (default empty). Extra Host
values union with the compiled loopback list; they do not replace it.
Literal IP Host headers are accepted without extras. Extra **hostnames**
use `LABLDAP_MANAGEMENT_ALLOWED_HOSTS` and `--management-allowed-host`.
Host-only entries match any port. `*` is rejected (ADR-0010).

`spec.management.metrics.enabled` defaults to true. `requireAuth` defaults
to false: treat `/metrics` as network-restricted (loopback or Compose
network policy). Set `requireAuth: true` when the listener is reachable
beyond the lab host. Labels never include DNs, usernames, request IDs,
token IDs, session IDs, filters, or passwords (OD-021).
