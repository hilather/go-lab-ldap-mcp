// Package api is the HTTP/REST transport.
//
// It decodes HTTP-specific inputs, maps authenticated principals to
// application commands, and renders responses. It must not contain LDAP
// filters, directory mutation logic, or imports of internal/mcpserver.
package api
