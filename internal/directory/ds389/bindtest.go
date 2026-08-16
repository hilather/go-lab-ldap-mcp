package ds389

import (
	"context"
	"strings"

	"github.com/go-ldap/ldap/v3"

	"github.com/hilather/go-lab-ldap-mcp/internal/config"
	"github.com/hilather/go-lab-ldap-mcp/internal/directory"
	"github.com/hilather/go-lab-ldap-mcp/internal/directory/ldapclient"
	"github.com/hilather/go-lab-ldap-mcp/internal/observability"
)

func (r *Runtime) BindTest(ctx context.Context, identity string, password observability.Secret, transport directory.Transport) (directory.BindTestResult, error) {
	// Identity is resolved on the pooled runtime session; the bind itself
	// always uses a disposable connection that is never returned to the pool.
	dn, found, disabled, locked, err := r.lookupBindIdentity(ctx, identity)
	if err != nil {
		return directory.BindTestResult{Outcome: directory.BindOutcomeUnavailable}, redactSecrets(err, password)
	}
	if dn == "" {
		rdn, rerr := config.BuildRDN("uid", strings.TrimSpace(identity))
		if rerr != nil {
			return directory.BindTestResult{Outcome: directory.BindOutcomeInvalidCredentials}, nil
		}
		dn = rdn + "," + r.cfg.PeopleDN
	}

	conn, err := r.dialBindTest(ctx, transport)
	if err != nil {
		return directory.BindTestResult{Outcome: directory.BindOutcomeUnavailable}, redactSecrets(err, password)
	}
	defer conn.Close()

	// Empty simple bind is an unauthenticated bind (389 result 53), not a
	// disabled account. Do not call Bind; still used a disposable conn.
	if password.Reveal() == "" {
		return directory.BindTestResult{Outcome: directory.BindOutcomeInvalidCredentials}, nil
	}

	bindErr := conn.Bind(ctx, dn, password)
	outcome := bindOutcome(found, disabled, locked, bindErr)
	if bindErr != nil && outcome == directory.BindOutcomeUnavailable {
		return directory.BindTestResult{Outcome: outcome}, redactSecrets(bindErr, password)
	}
	return directory.BindTestResult{Outcome: outcome}, nil
}

func (r *Runtime) lookupBindIdentity(ctx context.Context, identity string) (dn string, found, disabled, locked bool, err error) {
	identity = strings.TrimSpace(identity)
	if identity == "" {
		return "", false, false, false, nil
	}
	size, seconds := r.searchLimits()
	var target string
	if strings.Contains(identity, "=") {
		parsed, perr := config.ParseDN(identity)
		if perr != nil || !r.underPeople(parsed.String()) {
			return "", false, false, false, nil
		}
		target = parsed.String()
	} else {
		target, err = r.userDN(identity)
		if err != nil {
			return "", false, false, false, nil
		}
	}
	err = r.pool.Do(ctx, func(c *ldapclient.Conn) error {
		ent, e := searchBaseConn(ctx, c, target, []string{"uid", "nsAccountLock", "pwdAccountLockedTime", "accountUnlockTime"}, size, seconds)
		if e != nil {
			if fieldOf(e) == directory.FieldNotFound {
				return nil
			}
			return e
		}
		found = true
		dn = ent.DN
		disabled = accountLocked(ent)
		locked = accountLockStamped(ent)
		return nil
	})
	return dn, found, disabled, locked, err
}

func (r *Runtime) dialBindTest(ctx context.Context, transport directory.Transport) (*ldapclient.Conn, error) {
	cfg := r.cfg.Client
	cfg.BindDN = ""
	cfg.BindPassword = ""
	cfg.Dial = nil
	if transport != "" {
		cfg.Transport = transport
	}
	if r.cfg.Connect != nil {
		return r.cfg.Connect(ctx, cfg)
	}
	return ldapclient.Connect(ctx, cfg)
}

// accountLockStamped unions engine lock markers (D19 / RQ-2): native
// stamps pwdAccountLockedTime; 389 stamps accountUnlockTime.
func accountLockStamped(e *ldap.Entry) bool {
	if e == nil {
		return false
	}
	return len(e.GetEqualFoldAttributeValues("pwdAccountLockedTime")) > 0 ||
		len(e.GetEqualFoldAttributeValues("accountUnlockTime")) > 0
}

func accountInactivated(err error) bool {
	if err == nil {
		return false
	}
	// 389 uses LDAP 53 for inactivated accounts *and* unauthenticated binds.
	// Only the diagnostic distinguishes them; do not key off result code 53.
	msg := strings.ToLower(err.Error())
	return strings.Contains(msg, "inactivated") || strings.Contains(msg, "account disabled")
}

func bindOutcome(found, disabled, locked bool, bindErr error) string {
	if bindErr == nil {
		return directory.BindOutcomeSuccess
	}
	if disabled || accountInactivated(bindErr) {
		return directory.BindOutcomeDisabled
	}
	code := fieldOf(bindErr)
	switch code {
	case directory.FieldUnavailable:
		return directory.BindOutcomeUnavailable
	case directory.FieldForbidden:
		if disabled {
			return directory.BindOutcomeDisabled
		}
		if locked {
			return directory.BindOutcomeLocked
		}
		return directory.BindOutcomeInvalidCredentials
	case directory.FieldConstraint:
		if disabled {
			return directory.BindOutcomeDisabled
		}
		if locked {
			return directory.BindOutcomeLocked
		}
		return directory.BindOutcomeInvalidCredentials
	}
	if disabled {
		return directory.BindOutcomeDisabled
	}
	if locked && found {
		return directory.BindOutcomeLocked
	}
	return directory.BindOutcomeInvalidCredentials
}
