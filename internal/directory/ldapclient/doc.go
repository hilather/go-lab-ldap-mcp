// Package ldapclient is the runtime LDAP dialer, TLS, pool, escaping, and
// result-code adapter. It is the only runtime package allowed to import
// go-ldap. The bootstrap Directory Manager helper remains in ds389 and
// must not be deleted or reused by app/api/mcpserver.
package ldapclient
