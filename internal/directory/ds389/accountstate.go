package ds389

import (
	"context"
	"strings"
	"time"

	"github.com/go-ldap/ldap/v3"

	"github.com/hilather/go-lab-ldap-mcp/internal/directory"
	"github.com/hilather/go-lab-ldap-mcp/internal/directory/ldapclient"
)

const (
	attrPwdReset               = "pwdReset"
	attrPasswordExpirationTime = "passwordExpirationTime"
	attrAccountUnlockTime      = "accountUnlockTime"
	attrPasswordRetryCount     = "passwordRetryCount"
	pwdResetTrue               = "TRUE"
	passwordExpiredGeneralized = "19700101000000Z"
	permanentUnlockGeneralized = "20380119031407Z"
)

func (r *Runtime) AccountState(ctx context.Context, id directory.UserID) (directory.AccountState, error) {
	return r.readAccountState(ctx, id)
}

func (r *Runtime) ExpirePassword(ctx context.Context, id directory.UserID, rev directory.Revision) (directory.AccountState, error) {
	return r.mutateAccount(ctx, id, rev, func(mod *ldap.ModifyRequest, live *ldap.Entry) {
		mod.Replace(attrPwdReset, []string{pwdResetTrue})
		mod.Replace(attrPasswordExpirationTime, []string{passwordExpiredGeneralized})
	})
}

func (r *Runtime) ClearPasswordExpiry(ctx context.Context, id directory.UserID, rev directory.Revision) (directory.AccountState, error) {
	return r.mutateAccount(ctx, id, rev, func(mod *ldap.ModifyRequest, live *ldap.Entry) {
		if hasAttr(live, attrPwdReset) {
			mod.Delete(attrPwdReset, nil)
		}
		if hasAttr(live, attrPasswordExpirationTime) {
			mod.Delete(attrPasswordExpirationTime, nil)
		}
	})
}

func (r *Runtime) Lock(ctx context.Context, id directory.UserID, rev directory.Revision) (directory.AccountState, error) {
	now := time.Now().UTC().Format("20060102150405Z")
	return r.mutateAccount(ctx, id, rev, func(mod *ldap.ModifyRequest, live *ldap.Entry) {
		mod.Replace("pwdAccountLockedTime", []string{now})
		mod.Replace(attrAccountUnlockTime, []string{permanentUnlockGeneralized})
	})
}

func (r *Runtime) Unlock(ctx context.Context, id directory.UserID, rev directory.Revision) (directory.AccountState, error) {
	return r.mutateAccount(ctx, id, rev, func(mod *ldap.ModifyRequest, live *ldap.Entry) {
		if hasAttr(live, "pwdAccountLockedTime") {
			mod.Delete("pwdAccountLockedTime", nil)
		}
		if hasAttr(live, attrAccountUnlockTime) {
			mod.Delete(attrAccountUnlockTime, nil)
		}
		if hasAttr(live, attrPasswordRetryCount) {
			mod.Delete(attrPasswordRetryCount, nil)
		}
	})
}

func (r *Runtime) mutateAccount(ctx context.Context, id directory.UserID, rev directory.Revision, apply func(*ldap.ModifyRequest, *ldap.Entry)) (directory.AccountState, error) {
	dn, err := r.userDN(string(id))
	if err != nil {
		return directory.AccountState{}, err
	}
	if err := r.refuseRuntimeAccount(dn, "runtime account cannot be mutated"); err != nil {
		return directory.AccountState{}, err
	}
	size, seconds := r.searchLimits()
	var out directory.AccountState
	err = r.pool.Do(ctx, func(c *ldapclient.Conn) error {
		live, e := searchBaseConn(ctx, c, dn, accountStateReadAttrs(), size, seconds)
		if e != nil {
			return e
		}
		cur := userFromEntry(live, r.cfg.GroupsDN)
		if e := checkRev(cur.Revision, rev); e != nil {
			return e
		}
		mod := newModify(ctx, r, c, dn, live)
		r.afterSearch(ctx, dn)
		apply(mod, live)
		if len(mod.Changes) > 0 {
			if e := applyAccountChanges(ctx, c, dn, mod); e != nil {
				return e
			}
		}
		ent, e := searchBaseConn(ctx, c, dn, accountStateReadAttrs(), size, seconds)
		if e != nil {
			return e
		}
		out = accountStateFromEntry(string(id), ent, r.cfg.GroupsDN)
		return nil
	})
	return out, err
}

func (r *Runtime) readAccountState(ctx context.Context, id directory.UserID) (directory.AccountState, error) {
	dn, err := r.userDN(string(id))
	if err != nil {
		return directory.AccountState{}, err
	}
	size, seconds := r.searchLimits()
	var out directory.AccountState
	err = r.pool.Do(ctx, func(c *ldapclient.Conn) error {
		ent, e := searchBaseConn(ctx, c, dn, accountStateReadAttrs(), size, seconds)
		if e != nil {
			return e
		}
		out = accountStateFromEntry(string(id), ent, r.cfg.GroupsDN)
		return nil
	})
	return out, err
}

func accountStateReadAttrs() []string {
	return append(runtimeUserReadAttrs(), attrPwdReset, attrPasswordExpirationTime, attrAccountUnlockTime, "pwdAccountLockedTime")
}

func accountStateFromEntry(id string, e *ldap.Entry, groupsDN string) directory.AccountState {
	u := userFromEntry(e, groupsDN)
	return directory.AccountState{
		ID:         id,
		Enabled:    u.Enabled,
		Locked:     accountLockStamped(e),
		MustChange: accountMustChange(e),
		Revision:   u.Revision,
	}
}

func accountLockStamped(e *ldap.Entry) bool {
	if e == nil {
		return false
	}
	if len(e.GetAttributeValues("pwdAccountLockedTime")) > 0 {
		return true
	}
	return len(e.GetAttributeValues(attrAccountUnlockTime)) > 0
}

func accountMustChange(e *ldap.Entry) bool {
	if e == nil {
		return false
	}
	for _, v := range e.GetAttributeValues(attrPwdReset) {
		switch strings.ToLower(strings.TrimSpace(v)) {
		case "true", "1", "yes":
			return true
		}
	}
	raw := strings.TrimSpace(e.GetAttributeValue(attrPasswordExpirationTime))
	if raw == "" {
		return false
	}
	t, err := time.Parse("20060102150405Z", raw)
	if err != nil {
		t, err = time.Parse("20060102150405.000Z", raw)
	}
	if err != nil {
		return raw == passwordExpiredGeneralized
	}
	return !t.After(time.Now().UTC())
}

func hasAttr(e *ldap.Entry, name string) bool {
	return e != nil && len(e.GetAttributeValues(name)) > 0
}

func isUndefinedAttribute(err error) bool {
	if err == nil {
		return false
	}
	msg := strings.ToLower(err.Error())
	return strings.Contains(msg, "undefined attribute") ||
		strings.Contains(msg, "nosuchattribute") ||
		strings.Contains(msg, "no such attribute") ||
		strings.Contains(msg, "object class violation")
}

func applyAccountChanges(ctx context.Context, c *ldapclient.Conn, dn string, mod *ldap.ModifyRequest) error {
	if err := c.Modify(ctx, mod); err == nil {
		return nil
	} else if !isUndefinedAttribute(err) {
		return err
	} else {
		applied := 0
		// Combined modify is atomic: a schema/undefined failure leaves the
		// entry unchanged, so the first split can still carry the original
		// assertion. After one split succeeds, later splits must not reuse
		// that pre-image (entryCSN/modifyTimestamp have moved).
		controls := mod.Controls
		for _, ch := range mod.Changes {
			one := retryAccountModify(dn, ch, controls)
			if e := c.Modify(ctx, one); e != nil {
				if !isUndefinedAttribute(e) {
					return e
				}
				continue
			}
			applied++
			controls = nil
		}
		if applied == 0 {
			return err
		}
		return nil
	}
}

// retryAccountModify copies one change onto a new modify. controls may be
// the original assertion set, or nil after a prior split write succeeded.
func retryAccountModify(dn string, ch ldap.Change, controls []ldap.Control) *ldap.ModifyRequest {
	one := ldap.NewModifyRequest(dn, controls)
	one.Changes = []ldap.Change{ch}
	return one
}
