package ds389

import (
	"context"
	"strings"
	"time"

	"github.com/go-ldap/ldap/v3"

	"github.com/hilather/go-lab-ldap-mcp/internal/bootstrap"
	"github.com/hilather/go-lab-ldap-mcp/internal/config"
	"github.com/hilather/go-lab-ldap-mcp/internal/config/v1alpha1"
)

func (e Engine) ReconcileSeed(ctx context.Context, req bootstrap.SeedRequest) (bootstrap.SeedResult, error) {
	if req.DialTimeout <= 0 {
		req.DialTimeout = 5 * time.Second
	}
	dial := e.TreeDial
	if dial == nil {
		dial = defaultTreeDial
	}
	conn, err := dial(ctx, req.TreeRequest)
	if err != nil {
		return bootstrap.SeedResult{}, bootstrap.PhaseError("seed", "apply_failed", "could not bind as Directory Manager to apply seed data").Wrap(err)
	}
	defer conn.Close()

	if !req.Write {
		return inspectSeed(conn, req)
	}

	var res bootstrap.SeedResult
	if req.StartupMode == v1alpha1.StartupReset {
		deleted, err := e.deleteExtras(conn, req)
		if err != nil {
			return res, err
		}
		res.Deleted = deleted
	}
	for _, u := range req.Users {
		if err := ctx.Err(); err != nil {
			return res, bootstrap.PhaseError("seed", "apply_failed", "seed apply canceled").Wrap(err)
		}
		if err := e.upsertUser(conn, req, u, &res); err != nil {
			return res, err
		}
	}
	for _, g := range req.Groups {
		if err := ctx.Err(); err != nil {
			return res, bootstrap.PhaseError("seed", "apply_failed", "seed apply canceled").Wrap(err)
		}
		if err := e.upsertGroup(conn, g, &res); err != nil {
			return res, err
		}
	}
	for _, u := range req.Users {
		if !u.Enabled {
			continue
		}
		pw, err := seedPassword(u)
		if err != nil {
			return res, err
		}
		if err := e.bindSeedUser(ctx, req.TreeRequest, u.DN, pw); err != nil {
			return res, bootstrap.PhaseError("seed", "password_set", "enabled seed user could not bind").Wrap(err)
		}
	}
	return res, nil
}

func inspectSeed(conn treeConn, req bootstrap.SeedRequest) (bootstrap.SeedResult, error) {
	var res bootstrap.SeedResult
	for _, u := range req.Users {
		ok, err := entryExists(conn, u.DN)
		if err != nil {
			return res, bootstrap.PhaseError("seed", "apply_failed", "could not inspect seed user").Wrap(err)
		}
		if ok {
			res.Matched = append(res.Matched, u.DN)
		}
	}
	for _, g := range req.Groups {
		ok, err := entryExists(conn, g.DN)
		if err != nil {
			return res, bootstrap.PhaseError("seed", "apply_failed", "could not inspect seed group").Wrap(err)
		}
		if ok {
			res.Matched = append(res.Matched, g.DN)
		}
	}
	return res, nil
}

func (e Engine) upsertUser(conn treeConn, req bootstrap.SeedRequest, u config.NormalizedUser, res *bootstrap.SeedResult) error {
	pw, err := seedPassword(u)
	if err != nil {
		return err
	}
	ok, err := entryExists(conn, u.DN)
	if err != nil {
		return bootstrap.PhaseError("seed", "apply_failed", "could not read seed user").Wrap(err)
	}
	if !ok {
		if err := addUser(conn, u); err != nil {
			if !isAlreadyExists(err) {
				return bootstrap.PhaseError("seed", "apply_failed", "could not create seed user").Wrap(err)
			}
		} else {
			if err := e.setSeedPassword(conn, u.DN, pw); err != nil {
				if delErr := conn.Del(ldap.NewDelRequest(u.DN, nil)); delErr != nil {
					return bootstrap.PhaseError("seed", "partial", "could not remove incomplete seed user after password-set failure").Wrap(err)
				}
				return bootstrap.PhaseError("seed", "password_set", "could not set seed user password").Wrap(err)
			}
			res.Created = append(res.Created, u.DN)
			return nil
		}
	}
	live, err := readEntry(conn, u.DN, userReadAttrs(u))
	if err != nil {
		return bootstrap.PhaseError("seed", "apply_failed", "could not read seed user").Wrap(err)
	}
	changed := userNeedsUpdate(live, u)
	if changed {
		if err := modifyUser(conn, live, u); err != nil {
			return bootstrap.PhaseError("seed", "apply_failed", "could not update seed user").Wrap(err)
		}
	}
	if err := replacePassword(conn, u.DN, pw); err != nil {
		return bootstrap.PhaseError("seed", "password_set", "could not set seed user password").Wrap(err)
	}
	if changed {
		res.Updated = append(res.Updated, u.DN)
	} else {
		res.Matched = append(res.Matched, u.DN)
	}
	return nil
}

func (e Engine) upsertGroup(conn treeConn, g config.NormalizedGroup, res *bootstrap.SeedResult) error {
	members := memberDNs(g)
	if len(members) == 0 {
		return bootstrap.PhaseError("seed", "apply_failed", "seed group has no members")
	}
	ok, err := entryExists(conn, g.DN)
	if err != nil {
		return bootstrap.PhaseError("seed", "apply_failed", "could not read seed group").Wrap(err)
	}
	if !ok {
		if err := addGroup(conn, g, members); err != nil {
			if !isAlreadyExists(err) {
				return bootstrap.PhaseError("seed", "apply_failed", "could not create seed group").Wrap(err)
			}
		} else {
			res.Created = append(res.Created, g.DN)
			return nil
		}
	}
	live, err := readEntry(conn, g.DN, []string{"objectClass", "cn", "member"})
	if err != nil {
		return bootstrap.PhaseError("seed", "apply_failed", "could not read seed group").Wrap(err)
	}
	if !groupNeedsUpdate(live, g, members) {
		res.Matched = append(res.Matched, g.DN)
		return nil
	}
	mod := ldap.NewModifyRequest(g.DN, nil)
	mod.Replace("cn", []string{g.ID})
	mod.Replace("member", members)
	if err := conn.Modify(mod); err != nil {
		return bootstrap.PhaseError("seed", "apply_failed", "could not update seed group").Wrap(err)
	}
	res.Updated = append(res.Updated, g.DN)
	return nil
}

func (e Engine) deleteExtras(conn treeConn, req bootstrap.SeedRequest) ([]string, error) {
	keep := keepDNs(req)
	people, err := listChildren(conn, req.PeopleDN, []string{"dn", "objectClass"})
	if err != nil {
		return nil, bootstrap.PhaseError("seed", "apply_failed", "could not list people entries").Wrap(err)
	}
	groups, err := listChildren(conn, req.GroupsDN, []string{"dn", "objectClass", "member"})
	if err != nil {
		return nil, bootstrap.PhaseError("seed", "apply_failed", "could not list group entries").Wrap(err)
	}
	var extraPeople, extraGroups []*ldap.Entry
	for _, e := range people {
		if !kept(keep, e.DN) {
			extraPeople = append(extraPeople, e)
		}
	}
	for _, e := range groups {
		if !kept(keep, e.DN) {
			extraGroups = append(extraGroups, e)
		}
	}
	var deleted []string
	for _, e := range extraGroups {
		if onlyExtraMembers(e, keep) {
			if err := delIgnoreMissing(conn, e.DN); err != nil {
				return deleted, bootstrap.PhaseError("seed", "apply_failed", "could not delete extra group").Wrap(err)
			}
			deleted = append(deleted, e.DN)
		}
	}
	for _, e := range extraPeople {
		if err := delIgnoreMissing(conn, e.DN); err != nil {
			return deleted, bootstrap.PhaseError("seed", "apply_failed", "could not delete extra user").Wrap(err)
		}
		deleted = append(deleted, e.DN)
	}
	for _, e := range extraGroups {
		if onlyExtraMembers(e, keep) {
			continue
		}
		if err := delIgnoreMissing(conn, e.DN); err != nil {
			return deleted, bootstrap.PhaseError("seed", "apply_failed", "could not delete extra group").Wrap(err)
		}
		deleted = append(deleted, e.DN)
	}
	return deleted, nil
}

func (e Engine) setSeedPassword(conn treeConn, dn, password string) error {
	if e.SeedPasswordReplace != nil {
		return e.SeedPasswordReplace(dn, password)
	}
	return replacePassword(conn, dn, password)
}

func (e Engine) bindSeedUser(ctx context.Context, req bootstrap.TreeRequest, dn, password string) error {
	if e.SeedBind != nil {
		return e.SeedBind(ctx, req, dn, password)
	}
	return defaultSeedBind(ctx, req, dn, password)
}

func defaultSeedBind(ctx context.Context, req bootstrap.TreeRequest, dn, password string) error {
	conn, err := dialLDAP(ctx, req)
	if err != nil {
		return err
	}
	defer conn.Close()
	return conn.Bind(dn, password)
}

func addUser(conn treeConn, u config.NormalizedUser) error {
	add := ldap.NewAddRequest(u.DN, nil)
	add.Attribute("objectClass", userObjectClasses(u))
	add.Attribute("uid", []string{u.UID})
	add.Attribute("cn", []string{u.UID})
	add.Attribute("sn", []string{userSN(u)})
	if !u.Enabled {
		add.Attribute("nsAccountLock", []string{"true"})
	}
	for _, a := range u.Attributes {
		if skipPlannedUserAttr(a.Name) {
			continue
		}
		add.Attribute(a.Name, []string{a.Value})
	}
	return conn.Add(add)
}

func modifyUser(conn treeConn, live *ldap.Entry, u config.NormalizedUser) error {
	mod := ldap.NewModifyRequest(u.DN, nil)
	mod.Replace("cn", []string{u.UID})
	mod.Replace("sn", []string{userSN(u)})
	if !u.Enabled {
		mod.Replace("nsAccountLock", []string{"true"})
	} else if accountLocked(live) {
		mod.Delete("nsAccountLock", nil)
	}
	wantOC := userObjectClasses(u)
	if !hasAllObjectClasses(live, wantOC) {
		mod.Replace("objectClass", unionObjectClass(live, wantOC))
	}
	for _, a := range u.Attributes {
		if skipPlannedUserAttr(a.Name) {
			continue
		}
		mod.Replace(a.Name, []string{a.Value})
	}
	return conn.Modify(mod)
}

func addGroup(conn treeConn, g config.NormalizedGroup, members []string) error {
	add := ldap.NewAddRequest(g.DN, nil)
	add.Attribute("objectClass", []string{"top", "groupOfNames"})
	add.Attribute("cn", []string{g.ID})
	add.Attribute("member", members)
	return conn.Add(add)
}

func seedPassword(u config.NormalizedUser) (string, error) {
	if u.Password == nil {
		return "", bootstrap.PhaseError("seed", "password_set", "seed user password is not resolved")
	}
	pw := u.Password.Value.Reveal()
	if pw == "" {
		return "", bootstrap.PhaseError("seed", "password_set", "seed user password is empty")
	}
	return pw, nil
}

func userSN(u config.NormalizedUser) string {
	for _, a := range u.Attributes {
		if config.CanonicalAttr(a.Name) == "sn" && a.Value != "" {
			return a.Value
		}
	}
	return u.ID
}

func userObjectClasses(u config.NormalizedUser) []string {
	if len(u.ObjectClasses) > 0 {
		return append([]string(nil), u.ObjectClasses...)
	}
	return config.RequiredUserObjectClasses()
}

func skipPlannedUserAttr(name string) bool {
	if config.ForbiddenUserAttr(name) {
		return true
	}
	switch config.CanonicalAttr(name) {
	case "uid", "cn", "sn", "objectclass", "userpassword":
		return true
	default:
		return false
	}
}

func userReadAttrs(u config.NormalizedUser) []string {
	attrs := []string{"objectClass", "uid", "cn", "sn", "nsAccountLock"}
	seen := map[string]struct{}{
		"objectclass": {}, "uid": {}, "cn": {}, "sn": {}, "nsaccountlock": {},
	}
	for _, a := range u.Attributes {
		key := config.CanonicalAttr(a.Name)
		if skipPlannedUserAttr(a.Name) {
			continue
		}
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		attrs = append(attrs, a.Name)
	}
	return attrs
}

func userNeedsUpdate(e *ldap.Entry, u config.NormalizedUser) bool {
	if e == nil {
		return true
	}
	if !hasValue(e, "uid", u.UID) || !hasValue(e, "cn", u.UID) || !hasValue(e, "sn", userSN(u)) {
		return true
	}
	if u.Enabled == accountLocked(e) {
		return true
	}
	if !hasAllObjectClasses(e, userObjectClasses(u)) {
		return true
	}
	for _, a := range u.Attributes {
		if skipPlannedUserAttr(a.Name) {
			continue
		}
		if !hasValue(e, a.Name, a.Value) {
			return true
		}
	}
	return false
}

func groupNeedsUpdate(e *ldap.Entry, g config.NormalizedGroup, members []string) bool {
	if e == nil {
		return true
	}
	if !hasValue(e, "cn", g.ID) || !hasObjectClass(e, "groupOfNames") {
		return true
	}
	got := map[string]struct{}{}
	for _, m := range e.GetAttributeValues("member") {
		got[dnKey(m)] = struct{}{}
	}
	if len(got) != len(members) {
		return true
	}
	for _, m := range members {
		if _, ok := got[dnKey(m)]; !ok {
			return true
		}
	}
	return false
}

func memberDNs(g config.NormalizedGroup) []string {
	var out []string
	for _, m := range g.Members {
		if m.DN != "" {
			out = append(out, m.DN)
		}
	}
	return out
}

func keepDNs(req bootstrap.SeedRequest) map[string]struct{} {
	out := map[string]struct{}{}
	add := func(s string) {
		if s == "" {
			return
		}
		out[dnKey(s)] = struct{}{}
	}
	add(req.RuntimeDN)
	add(req.PeopleDN)
	add(req.GroupsDN)
	add(req.Suffix)
	for _, p := range req.Preserve {
		add(p)
	}
	for _, u := range req.Users {
		add(u.DN)
	}
	for _, g := range req.Groups {
		add(g.DN)
	}
	return out
}

func kept(keep map[string]struct{}, dn string) bool {
	_, ok := keep[dnKey(dn)]
	return ok
}

func onlyExtraMembers(e *ldap.Entry, keep map[string]struct{}) bool {
	for _, m := range e.GetAttributeValues("member") {
		if kept(keep, m) {
			return false
		}
	}
	return true
}

func listChildren(conn treeConn, base string, attrs []string) ([]*ldap.Entry, error) {
	if base == "" {
		return nil, nil
	}
	sr, err := conn.Search(&ldap.SearchRequest{
		BaseDN:     base,
		Scope:      ldap.ScopeSingleLevel,
		Filter:     "(objectClass=*)",
		Attributes: attrs,
	})
	if err != nil {
		if isNoSuchObject(err) {
			return nil, err
		}
		return nil, err
	}
	return sr.Entries, nil
}

func readEntry(conn treeConn, dn string, attrs []string) (*ldap.Entry, error) {
	sr, err := conn.Search(&ldap.SearchRequest{
		BaseDN:     dn,
		Scope:      ldap.ScopeBaseObject,
		Filter:     "(objectClass=*)",
		Attributes: attrs,
	})
	if err != nil {
		return nil, err
	}
	if len(sr.Entries) == 0 {
		return nil, ldap.NewError(ldap.LDAPResultNoSuchObject, nil)
	}
	return sr.Entries[0], nil
}

func delIgnoreMissing(conn treeConn, dn string) error {
	err := conn.Del(ldap.NewDelRequest(dn, nil))
	if err != nil && isNoSuchObject(err) {
		return nil
	}
	return err
}

func dnKey(s string) string {
	d, err := config.ParseDN(s)
	if err != nil {
		return strings.ToLower(strings.TrimSpace(s))
	}
	return d.String()
}

func hasValue(e *ldap.Entry, name, want string) bool {
	for _, v := range e.GetAttributeValues(name) {
		if strings.EqualFold(v, want) {
			return true
		}
	}
	return false
}

func hasObjectClass(e *ldap.Entry, name string) bool {
	return hasValue(e, "objectClass", name)
}

func hasAllObjectClasses(e *ldap.Entry, want []string) bool {
	for _, oc := range want {
		if !hasObjectClass(e, oc) {
			return false
		}
	}
	return true
}

func accountLocked(e *ldap.Entry) bool {
	return hasValue(e, "nsAccountLock", "true")
}

func unionObjectClass(e *ldap.Entry, want []string) []string {
	seen := map[string]string{}
	for _, v := range e.GetAttributeValues("objectClass") {
		seen[strings.ToLower(v)] = v
	}
	for _, w := range want {
		if _, ok := seen[strings.ToLower(w)]; !ok {
			seen[strings.ToLower(w)] = w
		}
	}
	out := make([]string, 0, len(seen))
	for _, v := range seen {
		out = append(out, v)
	}
	return out
}
