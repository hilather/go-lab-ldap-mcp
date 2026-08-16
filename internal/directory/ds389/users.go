package ds389

import (
	"context"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/go-ldap/ldap/v3"

	"github.com/hilather/go-lab-ldap-mcp/internal/config"
	"github.com/hilather/go-lab-ldap-mcp/internal/directory"
	"github.com/hilather/go-lab-ldap-mcp/internal/directory/ldapclient"
	"github.com/hilather/go-lab-ldap-mcp/internal/observability"
)

func (r *Runtime) List(ctx context.Context, q directory.UserListQuery) (directory.UserPage, error) {
	size, seconds := r.searchLimits()
	page := r.pageSize(q.PageSize)
	queryKey := "users|" + q.Q + "|" + strconv.Itoa(page)
	cookie, err := r.decodePageCursor(q.Cursor, queryKey)
	if err != nil {
		return directory.UserPage{}, err
	}
	filter := "(&(objectClass=inetOrgPerson)(uid=*))"
	if q.Q != "" {
		esc := ldapclient.EscapeFilter(q.Q)
		filter = "(&(objectClass=inetOrgPerson)(|(uid=*" + esc + "*)(cn=*" + esc + "*)(sn=*" + esc + "*)))"
	}
	var pageOut directory.UserPage
	err = r.pool.Do(ctx, func(c *ldapclient.Conn) error {
		res, next, e := c.SearchPage(ctx, &ldap.SearchRequest{
			BaseDN:       r.cfg.PeopleDN,
			Scope:        ldap.ScopeSingleLevel,
			DerefAliases: ldap.NeverDerefAliases,
			SizeLimit:    size,
			TimeLimit:    seconds,
			Filter:       filter,
			Attributes:   runtimeUserReadAttrs(),
		}, uint32(page), cookie)
		if e != nil {
			return e
		}
		for _, e := range res.Entries {
			pageOut.Items = append(pageOut.Items, userFromEntry(e, r.cfg.GroupsDN))
		}
		cur, e := r.encodePageCursor(queryKey, next)
		if e != nil {
			return e
		}
		pageOut.NextCursor = cur
		return nil
	})
	return pageOut, err
}

func (r *Runtime) Get(ctx context.Context, id directory.UserID) (directory.User, error) {
	dn, err := r.userDN(string(id))
	if err != nil {
		return directory.User{}, err
	}
	size, seconds := r.searchLimits()
	var out directory.User
	err = r.pool.Do(ctx, func(c *ldapclient.Conn) error {
		e, eerr := searchBaseConn(ctx, c, dn, runtimeUserReadAttrs(), size, seconds)
		if eerr != nil {
			return eerr
		}
		out = userFromEntry(e, r.cfg.GroupsDN)
		return nil
	})
	return out, err
}

func (r *Runtime) Add(ctx context.Context, spec directory.UserSpec) (directory.User, error) {
	if err := validateUserSpec(spec); err != nil {
		return directory.User{}, err
	}
	uid := spec.UID
	if uid == "" {
		uid = spec.ID
	}
	dn, err := r.userDN(uid)
	if err != nil {
		return directory.User{}, err
	}
	pw := spec.Password.Reveal()
	if pw == "" {
		return directory.User{}, cfgErr("password", "required", "password is required")
	}
	cn := attrMapValue(spec.Attributes, "cn")
	if cn == "" {
		cn = uid
	}
	sn := attrMapValue(spec.Attributes, "sn")
	if sn == "" {
		sn = spec.ID
	}
	enabled := true
	if spec.Enabled != nil {
		enabled = *spec.Enabled
	}
	add := ldap.NewAddRequest(dn, nil)
	add.Attribute("objectClass", config.RequiredUserObjectClasses())
	add.Attribute("uid", []string{uid})
	add.Attribute("cn", []string{cn})
	add.Attribute("sn", []string{sn})
	if !enabled {
		add.Attribute("nsAccountLock", []string{"true"})
	}
	for name, val := range spec.Attributes {
		if skipPlannedUserAttr(name) {
			continue
		}
		if forbiddenWriteAttr(name) {
			return directory.User{}, cfgErr("attributes."+name, "forbidden_attribute", "attribute is not allowed on users")
		}
		add.Attribute(name, []string{val})
	}
	size, seconds := r.searchLimits()
	var out directory.User
	err = r.pool.Do(ctx, func(c *ldapclient.Conn) error {
		if e := c.Add(ctx, add); e != nil {
			return e
		}
		if e := replaceUserPassword(ctx, c, dn, spec.Password); e != nil {
			_ = c.Del(ctx, ldap.NewDelRequest(dn, nil))
			return directory.Error("password", directory.FieldIncomplete, "user create did not complete")
		}
		ent, e := searchBaseConn(ctx, c, dn, runtimeUserReadAttrs(), size, seconds)
		if e != nil {
			return e
		}
		out = userFromEntry(ent, r.cfg.GroupsDN)
		return nil
	})
	return out, redactSecrets(err, spec.Password)
}

func (r *Runtime) Modify(ctx context.Context, id directory.UserID, patch directory.UserPatch, rev directory.Revision) (directory.User, error) {
	dn, err := r.userDN(string(id))
	if err != nil {
		return directory.User{}, err
	}
	if err := validateUserPatch(patch); err != nil {
		return directory.User{}, err
	}
	size, seconds := r.searchLimits()
	var out directory.User
	err = r.pool.Do(ctx, func(c *ldapclient.Conn) error {
		live, e := searchBaseConn(ctx, c, dn, runtimeUserReadAttrs(), size, seconds)
		if e != nil {
			return e
		}
		cur := userFromEntry(live, r.cfg.GroupsDN)
		if e := checkRev(cur.Revision, rev); e != nil {
			return e
		}
		if err := r.refuseRuntimeMutation(dn, patch); err != nil {
			return err
		}
		mod := newModify(ctx, r, c, dn, live)
		r.afterSearch(ctx, dn)
		if patch.Enabled != nil {
			applyEnabled(mod, live, *patch.Enabled)
		}
		for name, val := range patch.Attributes {
			if skipPlannedUserAttr(name) && config.CanonicalAttr(name) != "cn" && config.CanonicalAttr(name) != "sn" {
				if forbiddenWriteAttr(name) {
					return cfgErr("attributes."+name, "forbidden_attribute", "attribute is not allowed on users")
				}
				continue
			}
			if forbiddenWriteAttr(name) {
				return cfgErr("attributes."+name, "forbidden_attribute", "attribute is not allowed on users")
			}
			key := config.CanonicalAttr(name)
			if (key == "cn" || key == "sn") && strings.TrimSpace(val) == "" {
				return cfgErr("attributes."+name, "required", "schema-required attribute cannot be empty")
			}
			if strings.TrimSpace(val) == "" {
				// Empty value is the UserPatch delete signal (omit = leave).
				if live.GetAttributeValue(name) != "" {
					mod.Delete(name, nil)
				}
				continue
			}
			mod.Replace(name, []string{val})
		}
		if len(mod.Changes) > 0 {
			if e := c.Modify(ctx, mod); e != nil {
				return e
			}
		}
		ent, e := searchBaseConn(ctx, c, dn, runtimeUserReadAttrs(), size, seconds)
		if e != nil {
			return e
		}
		out = userFromEntry(ent, r.cfg.GroupsDN)
		return nil
	})
	return out, err
}

func (r *Runtime) SetEnabled(ctx context.Context, id directory.UserID, enabled bool, rev directory.Revision) (directory.User, error) {
	dn, err := r.userDN(string(id))
	if err != nil {
		return directory.User{}, err
	}
	if err := r.refuseRuntimeAccount(dn, "runtime account cannot be mutated"); err != nil {
		return directory.User{}, err
	}
	size, seconds := r.searchLimits()
	var out directory.User
	err = r.pool.Do(ctx, func(c *ldapclient.Conn) error {
		live, e := searchBaseConn(ctx, c, dn, runtimeUserReadAttrs(), size, seconds)
		if e != nil {
			return e
		}
		cur := userFromEntry(live, r.cfg.GroupsDN)
		if e := checkRev(cur.Revision, rev); e != nil {
			return e
		}
		if cur.Enabled == enabled {
			out = cur
			return nil
		}
		mod := newModify(ctx, r, c, dn, live)
		r.afterSearch(ctx, dn)
		if applyEnabled(mod, live, enabled) {
			if e := c.Modify(ctx, mod); e != nil {
				return e
			}
		}
		ent, e := searchBaseConn(ctx, c, dn, runtimeUserReadAttrs(), size, seconds)
		if e != nil {
			return e
		}
		out = userFromEntry(ent, r.cfg.GroupsDN)
		return nil
	})
	return out, err
}

func (r *Runtime) Delete(ctx context.Context, id directory.UserID, rev directory.Revision) error {
	dn, err := r.userDN(string(id))
	if err != nil {
		return err
	}
	if err := r.refuseRuntimeAccount(dn, "runtime account cannot be deleted"); err != nil {
		return err
	}
	size, seconds := r.searchLimits()
	return r.pool.Do(ctx, func(c *ldapclient.Conn) error {
		live, e := searchBaseConn(ctx, c, dn, runtimeUserReadAttrs(), size, seconds)
		if e != nil {
			return e
		}
		if e := checkRev(userFromEntry(live, r.cfg.GroupsDN).Revision, rev); e != nil {
			return e
		}
		r.afterSearch(ctx, dn)
		if e := c.Del(ctx, newDelete(ctx, r, c, dn, live)); e != nil {
			return e
		}
		return r.verifyUserRemovedFromGroups(ctx, c, dn)
	})
}

func (r *Runtime) SetPassword(ctx context.Context, id directory.UserID, password observability.Secret, rev directory.Revision, mustChange bool) error {
	dn, err := r.userDN(string(id))
	if err != nil {
		return err
	}
	if err := r.refuseRuntimeAccount(dn, "runtime account cannot be mutated"); err != nil {
		return err
	}
	if password.Reveal() == "" {
		return cfgErr("password", "required", "password is required")
	}
	size, seconds := r.searchLimits()
	err = r.pool.Do(ctx, func(c *ldapclient.Conn) error {
		live, e := searchBaseConn(ctx, c, dn, runtimeUserReadAttrs(), size, seconds)
		if e != nil {
			return e
		}
		if e := checkRev(userFromEntry(live, r.cfg.GroupsDN).Revision, rev); e != nil {
			return e
		}
		var controls []ldap.Control
		if ctl := r.assertionControl(ctx, c, live); ctl != nil {
			controls = append(controls, ctl)
		}
		r.afterSearch(ctx, dn)
		if e := replaceUserPassword(ctx, c, dn, password, controls...); e != nil {
			return e
		}
		stamps := ldap.NewModifyRequest(dn, nil)
		if mustChange {
			stamps.Replace(attrPwdReset, []string{pwdResetTrue})
			stamps.Replace(attrPasswordExpirationTime, []string{passwordExpiredGeneralized})
			return applyAccountChanges(ctx, c, dn, stamps)
		}
		// Best-effort: native hash-on-write already dropped these; 389
		// may keep them. Missing/undefined attributes are not a failed set.
		stamps.Delete(attrPwdReset, nil)
		stamps.Delete(attrPasswordExpirationTime, nil)
		_ = applyAccountChanges(ctx, c, dn, stamps)
		return nil
	})
	return redactSecrets(err, password)
}

func replaceUserPassword(ctx context.Context, c *ldapclient.Conn, dn string, password observability.Secret, controls ...ldap.Control) error {
	mod := ldap.NewModifyRequest(dn, controls)
	mod.Replace("userPassword", []string{password.Reveal()})
	return c.Modify(ctx, mod)
}

func applyEnabled(mod *ldap.ModifyRequest, live *ldap.Entry, enabled bool) bool {
	locked := accountLocked(live)
	if enabled {
		if !locked {
			return false
		}
		mod.Delete("nsAccountLock", nil)
		return true
	}
	if locked {
		return false
	}
	mod.Replace("nsAccountLock", []string{"true"})
	return true
}

func (r *Runtime) refuseRuntimeAccount(dn, public string) error {
	if r.cfg.RuntimeDN != "" && sameDN(dn, r.cfg.RuntimeDN) {
		return directory.Error("id", directory.FieldForbidden, public)
	}
	return nil
}

func (r *Runtime) refuseRuntimeMutation(dn string, patch directory.UserPatch) error {
	if patch.Enabled == nil {
		return nil
	}
	return r.refuseRuntimeAccount(dn, "runtime account cannot be mutated")
}

func validateUserSpec(spec directory.UserSpec) error {
	if err := parseSafeID(spec.ID, "id"); err != nil {
		return err
	}
	if spec.UID != "" {
		if err := parseSafeID(spec.UID, "uid"); err != nil {
			return err
		}
	}
	for name := range spec.Attributes {
		if forbiddenWriteAttr(name) {
			return cfgErr("attributes."+name, "forbidden_attribute", "attribute is not allowed on users")
		}
	}
	return nil
}

func validateUserPatch(patch directory.UserPatch) error {
	for name, val := range patch.Attributes {
		if forbiddenWriteAttr(name) {
			return cfgErr("attributes."+name, "forbidden_attribute", "attribute is not allowed on users")
		}
		if (config.CanonicalAttr(name) == "cn" || config.CanonicalAttr(name) == "sn") && strings.TrimSpace(val) == "" {
			return cfgErr("attributes."+name, "required", "schema-required attribute cannot be empty")
		}
	}
	return nil
}

func userFromEntry(e *ldap.Entry, groupsDN string) directory.User {
	if e == nil {
		return directory.User{}
	}
	uid := e.GetAttributeValue("uid")
	if uid == "" {
		uid = leafValue(e.DN)
	}
	var attrs []directory.AttrKV
	for _, a := range e.Attributes {
		name := config.CanonicalAttr(a.Name)
		if skipReturnedAttr(name) {
			continue
		}
		switch name {
		case "objectclass", "uid", "nsaccountlock", "memberof":
			continue
		}
		for _, v := range a.Values {
			attrs = append(attrs, directory.AttrKV{Name: name, Value: v})
		}
	}
	u := directory.User{
		ID:            uid,
		UID:           uid,
		DN:            e.DN,
		Enabled:       !accountLocked(e),
		ObjectClasses: sortCI(e.GetAttributeValues("objectClass")),
		Attributes:    sortAttrKV(attrs),
		Groups:        memberOfGroupIDs(e, groupsDN),
	}
	u.Revision = directory.RevisionOfUser(u)
	return u
}

func memberOfGroupIDs(e *ldap.Entry, groupsDN string) []directory.GroupID {
	if e == nil {
		return nil
	}
	var out []directory.GroupID
	seen := map[string]struct{}{}
	for _, v := range e.GetAttributeValues("memberOf") {
		if groupsDN != "" && !underContainer(v, groupsDN) {
			continue
		}
		id := leafValue(v)
		if id == "" {
			continue
		}
		key := strings.ToLower(id)
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		out = append(out, directory.GroupID(id))
	}
	sort.Slice(out, func(i, j int) bool { return out[i] < out[j] })
	return out
}

func revisionOfUser(u directory.User) directory.Revision {
	return directory.RevisionOfUser(u)
}

func (r *Runtime) verifyUserRemovedFromGroups(ctx context.Context, c *ldapclient.Conn, userDN string) error {
	size, seconds := r.searchLimits()
	filter := "(member=" + ldapclient.EscapeFilter(userDN) + ")"
	deadline := r.now().Add(2 * time.Second)
	for {
		res, err := c.Search(ctx, &ldap.SearchRequest{
			BaseDN:       r.cfg.GroupsDN,
			Scope:        ldap.ScopeSingleLevel,
			DerefAliases: ldap.NeverDerefAliases,
			SizeLimit:    size,
			TimeLimit:    seconds,
			Filter:       filter,
			Attributes:   []string{"dn"},
		})
		if err != nil && fieldOf(err) != directory.FieldNotFound {
			return err
		}
		if res == nil || len(res.Entries) == 0 {
			return nil
		}
		if r.now().After(deadline) {
			return directory.Error("member", directory.FieldConstraint, "referential integrity did not remove deleted user")
		}
		select {
		case <-ctx.Done():
			return ldapclient.MapError(ctx.Err())
		case <-time.After(50 * time.Millisecond):
		}
	}
}
