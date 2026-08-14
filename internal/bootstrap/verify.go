package bootstrap

import (
	"context"
	"time"

	"github.com/hilather/go-lab-ldap-mcp/internal/config"
)

// VerifyRequest is the runtime and application probe input. Dial fields
// live on TreeRequest. Write is unused by the verifiers themselves.
type VerifyRequest struct {
	TreeRequest
	Users     []config.NormalizedUser
	Groups    []config.NormalizedGroup
	Policy    config.NormalizedPolicy
	MarkerDN  string
	SizeLimit int
	TimeLimit time.Duration
}

// VerifyResult is secret-free. Counts only; never passwords.
type VerifyResult struct {
	Allowed        int
	Denied         int
	Skipped        int
	Binds          int
	Groups         int
	SkippedLockout int
}

// RuntimeVerifier proves compiled runtime allow and deny rights.
type RuntimeVerifier interface {
	VerifyRuntime(ctx context.Context, req VerifyRequest) (VerifyResult, error)
}

// AppVerifier proves seed binds, lockout isolation, disablement, and MemberOf.
type AppVerifier interface {
	VerifyApp(ctx context.Context, req VerifyRequest) (VerifyResult, error)
}
