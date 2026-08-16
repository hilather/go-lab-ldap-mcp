package native

import (
	"context"
	"strconv"
	"time"

	"github.com/hilather/go-lab-ldap-mcp/internal/bootstrap"
)

// ReconcilePolicy verifies the daemon's applied password policy against
// the compiled plan. labldapd self-applies the policy at start, so Write
// changes nothing here — the same read-back runs in both modes and any
// drift fails closed.
func (e Engine) ReconcilePolicy(ctx context.Context, req bootstrap.PolicyRequest) (bootstrap.PolicyResult, error) {
	pr, err := e.dmProbe(ctx, "pwpolicy", req.PasswordFile)
	if err != nil {
		return bootstrap.PolicyResult{}, err
	}
	defer func() { _ = pr.Close() }()

	p := req.Policy
	checks := []struct {
		attr string
		want string
	}{
		{attrPasswordScheme, canonicalScheme(p.StorageScheme)},
		{attrPasswordMinLength, strconv.Itoa(p.MinLength)},
		{attrPasswordHistory, strconv.Itoa(p.HistoryCount)},
		{attrPasswordMaxAge, seconds(p.MaxAge)},
		{attrLockoutEnabled, onOff(p.LockoutEnabled)},
		{attrLockoutMaxFailures, strconv.Itoa(p.MaxFailures)},
		{attrLockoutDuration, seconds(p.LockoutDuration)},
	}
	for _, c := range checks {
		if err := compareState(ctx, pr, "pwpolicy", "readback_mismatch", c.attr, c.want); err != nil {
			return bootstrap.PolicyResult{}, err
		}
	}
	// Applied mirrors the ds389 summary shape so bootstrap output is
	// engine-neutral. warningAge has no native engine counterpart and is
	// intentionally not read back (reported under T-144 notes).
	applied := []string{"storageScheme", "minLength", "historyCount", "maxAge", "lockout"}
	return bootstrap.PolicyResult{Applied: applied}, nil
}

func seconds(d time.Duration) string {
	n := int(d.Seconds())
	if n < 0 {
		n = 0
	}
	return strconv.Itoa(n)
}
