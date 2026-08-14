// Package directory defines transport-neutral repository interfaces and
// domain types. Public types in this package must not expose go-ldap,
// net/http, or MCP SDK types. Passwords on these interfaces are
// observability.Secret. Runtime LDAP I/O lives in ldapclient; the
// bootstrap Directory Manager helper stays in ds389.
package directory
