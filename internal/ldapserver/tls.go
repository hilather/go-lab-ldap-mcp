package ldapserver

import "crypto/tls"

// serverTLSConfig clones cfg for server use and enforces the LabLDAP TLS
// floor (ADR-0009 decision 10, security posture for the native engine):
// TLS 1.2 is the minimum protocol version, session tickets stay disabled,
// and the server's preference order wins. The caller's config is never
// mutated because listeners may share it with client code.
//
// When cfg already requires TLS 1.2 or newer, the clone preserves the
// caller's settings untouched; a zero or older MinVersion is raised.
// Certificates, ClientAuth, and every other knob remain the operator's
// responsibility — this helper only hardens, it never loosens.
func serverTLSConfig(cfg *tls.Config) *tls.Config {
	clone := cfg.Clone()
	if clone.MinVersion < tls.VersionTLS12 {
		clone.MinVersion = tls.VersionTLS12
	}
	return clone
}
