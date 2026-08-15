// Package ldapserver implements the native LabLDAP directory engine: an
// LDAPv3 listener, BER codec, operation dispatch, schema enforcement, ACI
// evaluation, and write-path plugins behind small interfaces. The persistent
// entry store lives in internal/ldapserver/store.
//
// This package is the server side of the "native" engine selected by
// spec.directory.engine (ADR-0008). It runs only as cmd/labldapd or
// in-process inside tests: production labldap and labldap-bootstrap binaries
// must not import it (ADR-0009 decision 3, enforced by tools/importboundary).
//
// Import rules (ADR-0009 rules 14-16): this package must not import
// internal/api, internal/mcpserver, internal/web, internal/auth, or
// internal/directory/ds389. It may import internal/config for pure DN,
// filter, and ACI-text helpers; it must not load YAML or act as an LDAP
// client of itself.
//
// T-124 landed the BER codec; T-125 the listener, connection lifecycle, and
// dispatch skeleton. The bbolt store (T-129), matching rules (T-131), and
// the ACI parser and evaluator (T-138, T-139) are still pending. The
// in-memory fakes in fakes.go satisfy the interfaces for later tasks' unit
// tests.
package ldapserver
