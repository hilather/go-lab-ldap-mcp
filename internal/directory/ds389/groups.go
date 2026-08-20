package ds389

import (
	"context"
	"strconv"
	"strings"
	"time"

	"github.com/go-ldap/ldap/v3"

	"github.com/hilather/go-lab-ldap-mcp/internal/config"
	"github.com/hilather/go-lab-ldap-mcp/internal/directory"
	"github.com/hilather/go-lab-ldap-mcp/internal/directory/ldapclient"
)

func (r *Runtime) listGroups(ctx context.Context, q directory.GroupListQuery) (directory.GroupPage, error) {
	size, seconds := r.searchLimits()
	page := r.pageSize(q.PageSize)
	queryKey := "groups|" + q.Q + "|" + strconv.Itoa(page)
	cookie, err := r.decodePageCursor(q.Cursor, queryKey)
	if err != nil {
		return directory.GroupPage{}, err
	}
	filter := "(objectClass=groupOfNames)"
	if q.Q != "" {
		esc := ldapclient.EscapeFilter(q.Q)
		filter = "(&(objectClass=groupOfNames)(cn=*" + esc + "*))"
	}
	var pageOut directory.GroupPage
	err = r.pool.Do(ctx, func(c *ldapclient.Conn) error {
		res, next, e := c.SearchPage(ctx, &ldap.SearchRequest{
			BaseDN:       r.cfg.GroupsDN,
			Scope:        ldap.ScopeSingleLevel,
			DerefAliases: ldap.NeverDerefAliases,
			SizeLimit:    size,
			TimeLimit:    seconds,
			Filter:       filter,
			Attributes:   groupReadAttrs(),
		}, uint32(page), cookie)
		if e != nil {
			return e
		}
		for _, e := range res.Entries {
			pageOut.Items = append(pageOut.Items, groupFromEntry(e, r.cfg.PeopleDN, r.cfg.GroupsDN))
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

func (r *Runtime) getGroup(ctx context.Context, id directory.GroupID) (directory.Group, error) {
	size, seconds := r.searchLimits()
	var out directory.Group
	err := r.pool.Do(ctx, func(c *ldapclient.Conn) error {
		dn, eerr := r.lookupGroupDN(ctx, c, string(id))
		if eerr != nil {
			return eerr
		}
		e, eerr := searchBaseConn(ctx, c, dn, groupReadAttrs(), size, seconds)
		if eerr != nil {
			return eerr
		}
		out = groupFromEntry(e, r.cfg.PeopleDN, r.cfg.GroupsDN)
		return nil
	})
	return out, err
}

func (r *Runtime) addGroup(ctx context.Context, spec directory.GroupSpec) (directory.Group, error) {
	if err := parseSafeID(spec.ID, "id"); err != nil {
		return directory.Group{}, err
	}
	if len(spec.Members) == 0 {
		return directory.Group{}, cfgErr("members", "empty_group", "groupOfNames cannot be empty")
	}
	dn, err := r.placeGroupDN(spec)
	if err != nil {
		return directory.Group{}, err
	}
	size, seconds := r.searchLimits()
	var out directory.Group
	err = r.pool.Do(ctx, func(c *ldapclient.Conn) error {
		if spec.DN != "" || spec.ParentDN != "" {
			parsed, perr := config.ParseDN(dn)
			if perr != nil {
				return perr
			}
			if e := r.requireParent(ctx, c, parsed); e != nil {
				return e
			}
		}
		resolved, e := r.resolveMembers(ctx, c, spec.Members, true)
		if e != nil {
			return e
		}
		if len(resolved) == 0 {
			return cfgErr("members", "empty_group", "groupOfNames cannot be empty")
		}
		add := ldap.NewAddRequest(dn, nil)
		add.Attribute("objectClass", []string{"top", "groupOfNames"})
		add.Attribute("cn", []string{spec.ID})
		add.Attribute("member", memberDNList(resolved))
		if e := c.Add(ctx, add); e != nil {
			return e
		}
		if e := r.verifyMembership(ctx, c, dn, resolved, nil); e != nil {
			return e
		}
		ent, e := searchBaseConn(ctx, c, dn, groupReadAttrs(), size, seconds)
		if e != nil {
			return e
		}
		out = groupFromEntry(ent, r.cfg.PeopleDN, r.cfg.GroupsDN)
		return nil
	})
	return out, err
}

func (r *Runtime) deleteGroup(ctx context.Context, id directory.GroupID, rev directory.Revision) error {
	size, seconds := r.searchLimits()
	return r.pool.Do(ctx, func(c *ldapclient.Conn) error {
		dn, e := r.lookupGroupDN(ctx, c, string(id))
		if e != nil {
			return e
		}
		live, e := searchBaseConn(ctx, c, dn, groupReadAttrs(), size, seconds)
		if e != nil {
			return e
		}
		g := groupFromEntry(live, r.cfg.PeopleDN, r.cfg.GroupsDN)
		if e := checkRev(g.Revision, rev); e != nil {
			return e
		}
		members := append([]directory.MemberRef(nil), g.Members...)
		r.afterSearch(ctx, dn)
		if e := c.Del(ctx, newDelete(ctx, r, c, dn, live)); e != nil {
			return e
		}
		return r.verifyMembership(ctx, c, dn, nil, members)
	})
}

func (r *Runtime) AddMembers(ctx context.Context, id directory.GroupID, members []directory.MemberRef, rev directory.Revision) (directory.MembershipSummary, error) {
	return r.mutateMembers(ctx, id, members, rev, memberAdd)
}

func (r *Runtime) RemoveMembers(ctx context.Context, id directory.GroupID, members []directory.MemberRef, rev directory.Revision) (directory.MembershipSummary, error) {
	return r.mutateMembers(ctx, id, members, rev, memberRemove)
}

func (r *Runtime) ReplaceMembers(ctx context.Context, id directory.GroupID, members []directory.MemberRef, rev directory.Revision) (directory.MembershipSummary, error) {
	return r.mutateMembers(ctx, id, members, rev, memberReplace)
}

type memberOp int

const (
	memberAdd memberOp = iota
	memberRemove
	memberReplace
)

func (r *Runtime) mutateMembers(ctx context.Context, id directory.GroupID, members []directory.MemberRef, rev directory.Revision, op memberOp) (directory.MembershipSummary, error) {
	size, seconds := r.searchLimits()
	var sum directory.MembershipSummary
	err := r.pool.Do(ctx, func(c *ldapclient.Conn) error {
		dn, e := r.lookupGroupDN(ctx, c, string(id))
		if e != nil {
			return e
		}
		live, e := searchBaseConn(ctx, c, dn, groupReadAttrs(), size, seconds)
		if e != nil {
			return e
		}
		cur := groupFromEntry(live, r.cfg.PeopleDN, r.cfg.GroupsDN)
		if e := checkRev(cur.Revision, rev); e != nil {
			return e
		}
		resolved, rejected, e := r.resolveMembersPartial(ctx, c, members)
		if e != nil {
			return e
		}
		sum = planMembership(cur.Members, resolved, rejected, op)
		if op != memberAdd && len(finalMembers(cur.Members, sum)) == 0 {
			return cfgErr("members", "empty_group", "groupOfNames cannot be empty")
		}
		if len(sum.Added) == 0 && len(sum.Removed) == 0 {
			sum.Revision = cur.Revision
			return nil
		}
		mod := newModify(ctx, r, c, dn, live)
		r.afterSearch(ctx, dn)
		switch op {
		case memberReplace:
			want := finalMembers(cur.Members, sum)
			if len(want) == 0 {
				return cfgErr("members", "empty_group", "groupOfNames cannot be empty")
			}
			mod.Replace("member", memberDNList(want))
		default:
			if add := memberDNList(sum.Added); len(add) > 0 {
				mod.Add("member", add)
			}
			if del := memberDNList(sum.Removed); len(del) > 0 {
				mod.Delete("member", del)
			}
		}
		if e := c.Modify(ctx, mod); e != nil {
			return e
		}
		if e := r.verifyMembership(ctx, c, dn, sum.Added, sum.Removed); e != nil {
			return e
		}
		ent, e := searchBaseConn(ctx, c, dn, groupReadAttrs(), size, seconds)
		if e != nil {
			return e
		}
		g := groupFromEntry(ent, r.cfg.PeopleDN, r.cfg.GroupsDN)
		sum.Revision = g.Revision
		return nil
	})
	return sum, err
}

func planMembership(current, incoming, rejected []directory.MemberRef, op memberOp) directory.MembershipSummary {
	have := memberIndex(current)
	sum := directory.MembershipSummary{Rejected: rejected}
	switch op {
	case memberReplace:
		want := memberIndex(incoming)
		for _, m := range incoming {
			if _, ok := have[dnKey(m.DN)]; ok {
				sum.Unchanged = append(sum.Unchanged, m)
			} else {
				sum.Added = append(sum.Added, m)
			}
		}
		for _, m := range current {
			if _, ok := want[dnKey(m.DN)]; !ok {
				sum.Removed = append(sum.Removed, m)
			}
		}
	case memberAdd:
		seen := map[string]struct{}{}
		for _, m := range incoming {
			key := dnKey(m.DN)
			if _, dup := seen[key]; dup {
				continue
			}
			seen[key] = struct{}{}
			if _, ok := have[key]; ok {
				sum.Unchanged = append(sum.Unchanged, m)
			} else {
				sum.Added = append(sum.Added, m)
			}
		}
	case memberRemove:
		seen := map[string]struct{}{}
		for _, m := range incoming {
			key := dnKey(m.DN)
			if _, dup := seen[key]; dup {
				continue
			}
			seen[key] = struct{}{}
			if _, ok := have[key]; ok {
				sum.Removed = append(sum.Removed, m)
			} else {
				sum.Unchanged = append(sum.Unchanged, m)
			}
		}
	}
	return sum
}

func finalMembers(current []directory.MemberRef, sum directory.MembershipSummary) []directory.MemberRef {
	drop := memberIndex(sum.Removed)
	out := make([]directory.MemberRef, 0, len(current)+len(sum.Added))
	seen := map[string]struct{}{}
	for _, m := range current {
		key := dnKey(m.DN)
		if _, ok := drop[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		out = append(out, m)
	}
	for _, m := range sum.Added {
		key := dnKey(m.DN)
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		out = append(out, m)
	}
	return out
}

func memberIndex(in []directory.MemberRef) map[string]directory.MemberRef {
	out := map[string]directory.MemberRef{}
	for _, m := range in {
		if m.DN == "" {
			continue
		}
		out[dnKey(m.DN)] = m
	}
	return out
}

func memberDNList(in []directory.MemberRef) []string {
	var out []string
	seen := map[string]struct{}{}
	for _, m := range in {
		if m.DN == "" {
			continue
		}
		key := dnKey(m.DN)
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		out = append(out, m.DN)
	}
	return out
}

func (r *Runtime) resolveMembers(ctx context.Context, c *ldapclient.Conn, members []directory.MemberRef, failFast bool) ([]directory.MemberRef, error) {
	resolved, rejected, err := r.resolveMembersPartial(ctx, c, members)
	if err != nil {
		return nil, err
	}
	if failFast && len(rejected) > 0 {
		m := rejected[0]
		path := "members"
		code := "missing_ref"
		msg := "member is not valid"
		if m.Kind == "group" && !r.cfg.NestedGroups && r.cfg.NestedMemberHook == nil {
			code = "nested_disabled"
			msg = "nested groups are disabled"
		}
		return nil, cfgErr(path, code, msg)
	}
	return resolved, nil
}

func (r *Runtime) resolveMembersPartial(ctx context.Context, c *ldapclient.Conn, members []directory.MemberRef) (resolved, rejected []directory.MemberRef, err error) {
	for _, m := range members {
		got, e := r.resolveMember(ctx, c, m)
		if e != nil {
			if fieldOf(e) == directory.FieldNotFound || hasField(e, "", "missing_ref") || hasField(e, "", "nested_disabled") || hasField(e, "", "invalid_member") {
				rejected = append(rejected, m)
				continue
			}
			return nil, nil, e
		}
		resolved = append(resolved, got)
	}
	return resolved, rejected, nil
}

func (r *Runtime) resolveMember(ctx context.Context, c *ldapclient.Conn, m directory.MemberRef) (directory.MemberRef, error) {
	kind := strings.ToLower(strings.TrimSpace(m.Kind))
	if m.DN != "" && kind == "" {
		switch {
		case r.underPeople(m.DN):
			kind = "user"
		case r.underGroups(m.DN):
			kind = "group"
		case r.underManaged(m.DN):
			kind = "user"
		default:
			return directory.MemberRef{}, cfgErr("members", "invalid_member", "member DN is outside managed suffixes")
		}
	}
	switch kind {
	case "", "user":
		kind = "user"
		if m.DN == "" {
			if err := parseSafeID(m.ID, "members"); err != nil {
				return directory.MemberRef{}, err
			}
			dn, err := r.lookupUserDN(ctx, c, m.ID)
			if err != nil {
				return directory.MemberRef{}, err
			}
			m.DN = dn
		}
		if !r.underManaged(m.DN) {
			return directory.MemberRef{}, cfgErr("members", "invalid_member", "user member is outside managed suffixes")
		}
		if m.ID == "" {
			m.ID = leafValue(m.DN)
		}
	case "group":
		if err := r.checkNested(m); err != nil {
			return directory.MemberRef{}, err
		}
		if m.DN == "" {
			if err := parseSafeID(m.ID, "members"); err != nil {
				return directory.MemberRef{}, err
			}
			dn, err := r.lookupGroupDN(ctx, c, m.ID)
			if err != nil {
				return directory.MemberRef{}, err
			}
			m.DN = dn
		}
		if !r.underManaged(m.DN) {
			return directory.MemberRef{}, cfgErr("members", "invalid_member", "group member is outside managed suffixes")
		}
		if m.ID == "" {
			m.ID = leafValue(m.DN)
		}
	default:
		return directory.MemberRef{}, cfgErr("members", "invalid_member", "member must be user or group")
	}
	m.Kind = kind
	size, seconds := r.searchLimits()
	ok, err := existsConn(ctx, c, m.DN, size, seconds)
	if err != nil {
		return directory.MemberRef{}, err
	}
	if !ok {
		return directory.MemberRef{}, cfgErr("members", "missing_ref", "member does not exist")
	}
	return m, nil
}

func (r *Runtime) checkNested(m directory.MemberRef) error {
	if r.cfg.NestedMemberHook != nil {
		return r.cfg.NestedMemberHook(m)
	}
	if !r.cfg.NestedGroups {
		return cfgErr("members", "nested_disabled", "nested groups are disabled")
	}
	return nil
}

func (r *Runtime) verifyMembership(ctx context.Context, c *ldapclient.Conn, groupDN string, added, removed []directory.MemberRef) error {
	size, seconds := r.searchLimits()
	deadline := r.now().Add(2 * time.Second)
	for {
		ok := true
		for _, m := range added {
			if m.Kind != "user" {
				continue
			}
			ent, err := searchBaseConn(ctx, c, m.DN, []string{"memberOf"}, size, seconds)
			if err != nil || !hasValue(ent, "memberOf", groupDN) {
				ok = false
				break
			}
		}
		if ok {
			for _, m := range removed {
				if m.Kind != "user" {
					continue
				}
				ent, err := searchBaseConn(ctx, c, m.DN, []string{"memberOf"}, size, seconds)
				if err != nil && fieldOf(err) != directory.FieldNotFound {
					return err
				}
				if ent != nil && hasValue(ent, "memberOf", groupDN) {
					ok = false
					break
				}
			}
		}
		if ok {
			return nil
		}
		if r.now().After(deadline) {
			return directory.Error("member", directory.FieldConstraint, "MemberOf or referential integrity did not match the write")
		}
		select {
		case <-ctx.Done():
			return ldapclient.MapError(ctx.Err())
		case <-time.After(50 * time.Millisecond):
		}
	}
}

func groupFromEntry(e *ldap.Entry, peopleDN, groupsDN string) directory.Group {
	if e == nil {
		return directory.Group{}
	}
	id := e.GetAttributeValue("cn")
	if id == "" {
		id = leafValue(e.DN)
	}
	g := directory.Group{
		ID:      id,
		DN:      e.DN,
		Members: membersFromEntry(e, peopleDN, groupsDN),
	}
	g.Revision = directory.RevisionOfGroup(g)
	return g
}

func membersFromEntry(e *ldap.Entry, peopleDN, groupsDN string) []directory.MemberRef {
	var out []directory.MemberRef
	seen := map[string]struct{}{}
	for _, dn := range e.GetAttributeValues("member") {
		key := dnKey(dn)
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		m := directory.MemberRef{DN: dn, ID: leafValue(dn)}
		switch {
		case underContainer(dn, groupsDN):
			m.Kind = "group"
		default:
			m.Kind = "user"
		}
		out = append(out, m)
	}
	return out
}

func revisionOfGroup(g directory.Group) directory.Revision {
	return directory.RevisionOfGroup(g)
}

// UserRepository and GroupRepository both define List/Get/Add/Delete.
// Go methods cannot overload; groups use the shared names via distinct
// receiver wrappers in the interface assertion helpers below.
var (
	_ directory.UserRepository  = (*userRepo)(nil)
	_ directory.GroupRepository = (*groupRepo)(nil)
)

type userRepo struct{ *Runtime }

type groupRepo struct{ *Runtime }

func (r *Runtime) Users() directory.UserRepository   { return userRepo{r} }
func (r *Runtime) Groups() directory.GroupRepository { return groupRepo{r} }

func (u userRepo) List(ctx context.Context, q directory.UserListQuery) (directory.UserPage, error) {
	return u.Runtime.List(ctx, q)
}
func (u userRepo) Get(ctx context.Context, id directory.UserID) (directory.User, error) {
	return u.Runtime.Get(ctx, id)
}
func (u userRepo) Add(ctx context.Context, spec directory.UserSpec) (directory.User, error) {
	return u.Runtime.Add(ctx, spec)
}
func (u userRepo) Delete(ctx context.Context, id directory.UserID, rev directory.Revision) error {
	return u.Runtime.Delete(ctx, id, rev)
}

func (g groupRepo) List(ctx context.Context, q directory.GroupListQuery) (directory.GroupPage, error) {
	return g.Runtime.listGroups(ctx, q)
}
func (g groupRepo) Get(ctx context.Context, id directory.GroupID) (directory.Group, error) {
	return g.Runtime.getGroup(ctx, id)
}
func (g groupRepo) Add(ctx context.Context, spec directory.GroupSpec) (directory.Group, error) {
	return g.Runtime.addGroup(ctx, spec)
}
func (g groupRepo) Delete(ctx context.Context, id directory.GroupID, rev directory.Revision) error {
	return g.Runtime.deleteGroup(ctx, id, rev)
}
