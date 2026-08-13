package bootstrap

import (
	"context"

	"github.com/hilather/go-lab-ldap-mcp/internal/config"
)

// ACIRequest is the named-ACI reconcile input. Dial fields are on TreeRequest.
type ACIRequest struct {
	TreeRequest
	ACIs []config.NamedACI
}

// ACIResult is secret-free.
type ACIResult struct {
	Applied []string
	Matched []string
}

// ACIReconciler applies or verifies compiled named ACIs.
type ACIReconciler interface {
	ReconcileACIs(ctx context.Context, req ACIRequest) (ACIResult, error)
}
