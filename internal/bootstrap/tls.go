package bootstrap

import (
	"context"
	"time"

	"github.com/hilather/go-lab-ldap-mcp/internal/observability"
)

// TLSRequest is the engine TLS/auth reconcile input. Passwords are
// Secret-wrapped or referenced by file path for dsconf.
type TLSRequest struct {
	PasswordFile   string
	Instance       string
	LDAPURL        string
	LDAPAddr       string
	LDAPSAddr      string
	CAFile         string
	Host           string
	UseLDAPS       bool
	StartTLS       bool
	Insecure       bool
	AllowCleartext bool
	AllowAnonymous bool
	RequiredSASL   []string
	BindDN         string
	Password       observability.Secret
	Write          bool
	DialTimeout    time.Duration
}

// TLSResult is secret-free.
type TLSResult struct {
	Transports []string
	SASL       []string
}

// TLSReconciler verifies (and optionally writes) directory TLS/auth policy.
type TLSReconciler interface {
	ReconcileTLS(ctx context.Context, req TLSRequest) (TLSResult, error)
}
