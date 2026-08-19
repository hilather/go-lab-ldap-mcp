package ds389

import (
	"context"
	"strings"

	"github.com/hilather/go-lab-ldap-mcp/internal/config"
	"github.com/hilather/go-lab-ldap-mcp/internal/directory"
	"github.com/hilather/go-lab-ldap-mcp/internal/directory/ldapclient"
	"github.com/hilather/go-lab-ldap-mcp/internal/observability"
)

func (r *Runtime) BindTest(ctx context.Context, identity string, password observability.Secret, transport directory.Transport) (directory.BindTestResult, error) {
	// Identity is resolved on the pooled runtime session; the bind itself
	// always uses a disposable connection that is never returned to the pool.
	dn, found, disabled, locked, mustChange, err := r.lookupBindIdentity(ctx, identity)
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
	outcome := bindOutcome(found, disabled, locked, mustChange, bindErr)
	if bindErr != nil && outcome == directory.BindOutcomeUnavailable {
		return directory.BindTestResult{Outcome: outcome}, redactSecrets(bindErr, password)
	}
	return directory.BindTestResult{Outcome: outcome}, nil
}

func (r *Runtime) lookupBindIdentity(ctx context.Context, identity string) (dn string, found, disabled, locked, mustChange bool, err error) {
	identity = strings.TrimSpace(identity)
	if identity == "" {
		return "", false, false, false, false, nil
	}
	size, seconds := r.searchLimits()
	var target string
	if strings.Contains(identity, "=") {
		parsed, perr := config.ParseDN(identity)
		if perr != nil || !r.underManaged(parsed.String()) {
			return "", false, false, false, false, nil
		}
		target = parsed.String()
	} else {
		err = r.pool.Do(ctx, func(c *ldapclient.Conn) error {
			got, e := r.lookupUserDN(ctx, c, identity)
			if e != nil {
				if fieldOf(e) == directory.FieldNotFound {
					return nil
				}
				return e
			}
			target = got
			return nil
		})
		if err != nil {
			return "", false, false, false, false, err
		}
		if target == "" {
			return "", false, false, false, false, nil
		}
	}
	err = r.pool.Do(ctx, func(c *ldapclient.Conn) error {
		ent, e := searchBaseConn(ctx, c, target, accountStateReadAttrs(), size, seconds)
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
		mustChange = accountMustChange(ent)
		return nil
	})
	return dn, found, disabled, locked, mustChange, err
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

func accountInactivated(err error) bool {
	if err == nil {
		return false
	}
	// 389 uses LDAP 53 for inactivated accounts *and* unauthenticated binds.
	// Only the diagnostic distinguishes them; do not key off result code 53.
	msg := strings.ToLower(err.Error())
	return strings.Contains(msg, "inactivated") || strings.Contains(msg, "account disabled")
}

func bindOutcome(found, disabled, locked, mustChange bool, bindErr error) string {
	if bindErr == nil {
		// Stamps win over a successful simple bind. 389 may still allow
		// LDAP bind when expire/lockout plugins are off; bind-test is the
		// QA view of account state.
		if disabled {
			return directory.BindOutcomeDisabled
		}
		if locked {
			return directory.BindOutcomeLocked
		}
		if mustChange {
			return directory.BindOutcomeMustChange
		}
		return directory.BindOutcomeSuccess
	}
	if disabled || accountInactivated(bindErr) {
		return directory.BindOutcomeDisabled
	}
	if passwordMustChangeDiag(bindErr) {
		return directory.BindOutcomeMustChange
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
		if mustChange {
			return directory.BindOutcomeMustChange
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

func passwordMustChangeDiag(err error) bool {
	if err == nil {
		return false
	}
	msg := strings.ToLower(err.Error())
	return strings.Contains(msg, "password expired") || strings.Contains(msg, "must be reset") || strings.Contains(msg, "must change")
}
