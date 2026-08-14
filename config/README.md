# Configuration

JSON Schema, examples, and the `v1alpha1` stand-in land in T-009–T-023.
`internal/config` must not connect to LDAP.

`spec.management.metrics.enabled` defaults to true. `requireAuth` defaults
to false: treat `/metrics` as network-restricted (loopback or Compose
network policy). Set `requireAuth: true` when the listener is reachable
beyond the lab host. Labels never include DNs, usernames, request IDs,
token IDs, session IDs, filters, or passwords (OD-021).
