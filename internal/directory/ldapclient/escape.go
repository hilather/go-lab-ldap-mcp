package ldapclient

import "github.com/go-ldap/ldap/v3"

// EscapeFilter escapes an untrusted value for inclusion in an LDAP filter.
func EscapeFilter(s string) string { return ldap.EscapeFilter(s) }

// EscapeDN escapes an untrusted value for inclusion in a DN/RDN.
func EscapeDN(s string) string { return ldap.EscapeDN(s) }
