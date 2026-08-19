package native

import (
	"context"

	"github.com/hilather/go-lab-ldap-mcp/internal/bootstrap"
	"github.com/hilather/go-lab-ldap-mcp/internal/config"
)

// Reconcile verifies the running labldapd applied the planned suffix.
// There is no native backend to create: the daemon self-applies the
// engine plan at start, so Write has no mutation to perform — the
// read-back runs identically in validate and apply modes and any
// mismatch fails closed.
func (e Engine) Reconcile(ctx context.Context, req bootstrap.BackendRequest) (bootstrap.BackendResult, error) {
	wantDN, err := config.ParseDN(req.Suffix)
	if err != nil {
		return bootstrap.BackendResult{}, bootstrap.PhaseError("backend", "conflict", "configured suffix is not a valid DN")
	}
	pr, err := e.dmProbe(ctx, "backend", req.PasswordFile)
	if err != nil {
		return bootstrap.BackendResult{}, err
	}
	defer func() { _ = pr.Close() }()

	if err := compareState(ctx, pr, "backend", "engine_mismatch", attrEngine, engineName); err != nil {
		return bootstrap.BackendResult{}, err
	}
	if err := compareState(ctx, pr, "backend", "readback_mismatch", attrEngineSuffix, wantDN.String()); err != nil {
		return bootstrap.BackendResult{}, err
	}
	for _, extra := range req.Additional {
		got, err := config.ParseDN(extra.Suffix)
		if err != nil {
			return bootstrap.BackendResult{}, bootstrap.PhaseError("backend", "conflict", "additional suffix is not a valid DN")
		}
		if err := compareState(ctx, pr, "backend", "readback_mismatch", attrEngineAdditional, got.String()); err != nil {
			return bootstrap.BackendResult{}, err
		}
	}
	return bootstrap.BackendResult{Action: "matched", Name: req.Name, Suffix: wantDN.String()}, nil
}
