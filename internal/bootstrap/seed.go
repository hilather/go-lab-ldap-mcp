package bootstrap

import (
	"context"

	"github.com/hilather/go-lab-ldap-mcp/internal/config"
)

// SeedRequest is the user/group/membership reconcile input. Dial fields
// and the write gate live on TreeRequest.
type SeedRequest struct {
	TreeRequest
	Users       []config.NormalizedUser
	Groups      []config.NormalizedGroup
	StartupMode string
	Preserve    []string
}

// SeedResult is secret-free. DNs only; never passwords.
type SeedResult struct {
	Created []string
	Updated []string
	Matched []string
	Deleted []string
}

// SeedReconciler applies or count-inspects compiled users and groups.
type SeedReconciler interface {
	ReconcileSeed(ctx context.Context, req SeedRequest) (SeedResult, error)
}
