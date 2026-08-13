package bootstrap

import (
	"context"

	"github.com/hilather/go-lab-ldap-mcp/internal/config"
)

// PolicyRequest is the global password-policy reconcile input.
type PolicyRequest struct {
	PasswordFile string
	Instance     string
	Policy       config.NormalizedPolicy
	Write        bool
}

// PolicyResult is secret-free.
type PolicyResult struct {
	Applied []string
}

// PolicyReconciler applies or verifies the compiled global password policy.
type PolicyReconciler interface {
	ReconcilePolicy(ctx context.Context, req PolicyRequest) (PolicyResult, error)
}
