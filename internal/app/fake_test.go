package app

import (
	"context"
	"io"
	"strings"
	"sync"

	"github.com/hilather/go-lab-ldap-mcp/internal/directory"
	"github.com/hilather/go-lab-ldap-mcp/internal/observability"
)

type fakeUsers struct {
	mu        sync.Mutex
	byID      map[directory.UserID]directory.User
	addErr    error
	modErr    error
	delErr    error
	getErr    error
	listErr   error
	pwErr     error
	leftover  bool
	deleted   []directory.UserID
	passwords map[directory.UserID]string
}

func newFakeUsers() *fakeUsers {
	return &fakeUsers{byID: map[directory.UserID]directory.User{}, passwords: map[directory.UserID]string{}}
}

func (f *fakeUsers) put(u directory.User) directory.User {
	if u.Revision == "" {
		u.Revision = directory.RevisionOfUser(u)
	}
	f.byID[directory.UserID(u.ID)] = u
	return u
}

func (f *fakeUsers) List(context.Context, directory.UserListQuery) (directory.UserPage, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.listErr != nil {
		return directory.UserPage{}, f.listErr
	}
	var items []directory.User
	for _, u := range f.byID {
		items = append(items, u)
	}
	return directory.UserPage{Items: items}, nil
}

func (f *fakeUsers) Get(_ context.Context, id directory.UserID) (directory.User, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.getErr != nil {
		return directory.User{}, f.getErr
	}
	u, ok := f.byID[id]
	if !ok {
		return directory.User{}, directory.Error("entry", directory.FieldNotFound, "directory entry not found")
	}
	return u, nil
}

func (f *fakeUsers) Add(_ context.Context, spec directory.UserSpec) (directory.User, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	id := directory.UserID(spec.ID)
	if _, ok := f.byID[id]; ok {
		return directory.User{}, directory.Error("entry", directory.FieldConflict, "directory entry already exists")
	}
	u := directory.User{ID: spec.ID, UID: spec.UID, Enabled: true, Attributes: kvFromMap(spec.Attributes)}
	if u.UID == "" {
		u.UID = spec.ID
	}
	if spec.Enabled != nil {
		u.Enabled = *spec.Enabled
	}
	u.Revision = directory.RevisionOfUser(u)
	if f.addErr != nil {
		if f.leftover {
			f.byID[id] = u
		}
		return directory.User{}, f.addErr
	}
	f.byID[id] = u
	f.passwords[id] = spec.Password.Reveal()
	return u, nil
}

func (f *fakeUsers) Modify(_ context.Context, id directory.UserID, patch directory.UserPatch, rev directory.Revision) (directory.User, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.modErr != nil {
		return directory.User{}, f.modErr
	}
	u, ok := f.byID[id]
	if !ok {
		return directory.User{}, directory.Error("entry", directory.FieldNotFound, "directory entry not found")
	}
	if rev != "" && u.Revision != rev {
		return directory.User{}, directory.Error("revision", directory.FieldConflict, "directory entry revision does not match")
	}
	if patch.Enabled != nil {
		u.Enabled = *patch.Enabled
	}
	attrs := map[string]string{}
	for _, a := range u.Attributes {
		attrs[a.Name] = a.Value
	}
	for k, v := range patch.Attributes {
		attrs[k] = v
	}
	u.Attributes = kvFromMap(attrs)
	u.Revision = directory.RevisionOfUser(u)
	f.byID[id] = u
	return u, nil
}

func (f *fakeUsers) SetEnabled(_ context.Context, id directory.UserID, enabled bool, rev directory.Revision) (directory.User, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	u, ok := f.byID[id]
	if !ok {
		return directory.User{}, directory.Error("entry", directory.FieldNotFound, "directory entry not found")
	}
	if rev != "" && u.Revision != rev {
		return directory.User{}, directory.Error("revision", directory.FieldConflict, "directory entry revision does not match")
	}
	u.Enabled = enabled
	u.Revision = directory.RevisionOfUser(u)
	f.byID[id] = u
	return u, nil
}

func (f *fakeUsers) Delete(_ context.Context, id directory.UserID, rev directory.Revision) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.delErr != nil {
		return f.delErr
	}
	u, ok := f.byID[id]
	if !ok {
		return directory.Error("entry", directory.FieldNotFound, "directory entry not found")
	}
	if rev != "" && u.Revision != rev {
		return directory.Error("revision", directory.FieldConflict, "directory entry revision does not match")
	}
	delete(f.byID, id)
	f.deleted = append(f.deleted, id)
	return nil
}

func (f *fakeUsers) SetPassword(_ context.Context, id directory.UserID, password observability.Secret, rev directory.Revision) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.pwErr != nil {
		return f.pwErr
	}
	u, ok := f.byID[id]
	if !ok {
		return directory.Error("entry", directory.FieldNotFound, "directory entry not found")
	}
	if rev != "" && u.Revision != rev {
		return directory.Error("revision", directory.FieldConflict, "directory entry revision does not match")
	}
	f.passwords[id] = password.Reveal()
	return nil
}

type fakeGroups struct {
	mu     sync.Mutex
	byID   map[directory.GroupID]directory.Group
	addErr error
	delErr error
	getErr error
}

func newFakeGroups() *fakeGroups {
	return &fakeGroups{byID: map[directory.GroupID]directory.Group{}}
}

func (f *fakeGroups) put(g directory.Group) directory.Group {
	g.Revision = directory.RevisionOfGroup(g)
	f.byID[directory.GroupID(g.ID)] = g
	return g
}

func (f *fakeGroups) List(context.Context, directory.GroupListQuery) (directory.GroupPage, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	var items []directory.Group
	for _, g := range f.byID {
		items = append(items, g)
	}
	return directory.GroupPage{Items: items}, nil
}

func (f *fakeGroups) Get(_ context.Context, id directory.GroupID) (directory.Group, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.getErr != nil {
		return directory.Group{}, f.getErr
	}
	g, ok := f.byID[id]
	if !ok {
		return directory.Group{}, directory.Error("entry", directory.FieldNotFound, "directory entry not found")
	}
	return g, nil
}

func (f *fakeGroups) Add(_ context.Context, spec directory.GroupSpec) (directory.Group, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.addErr != nil {
		return directory.Group{}, f.addErr
	}
	if _, ok := f.byID[directory.GroupID(spec.ID)]; ok {
		return directory.Group{}, directory.Error("entry", directory.FieldConflict, "directory entry already exists")
	}
	g := directory.Group{ID: spec.ID, Members: spec.Members}
	g.Revision = directory.RevisionOfGroup(g)
	f.byID[directory.GroupID(spec.ID)] = g
	return g, nil
}

func (f *fakeGroups) Delete(_ context.Context, id directory.GroupID, rev directory.Revision) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.delErr != nil {
		return f.delErr
	}
	g, ok := f.byID[id]
	if !ok {
		return directory.Error("entry", directory.FieldNotFound, "directory entry not found")
	}
	if rev != "" && g.Revision != rev {
		return directory.Error("revision", directory.FieldConflict, "directory entry revision does not match")
	}
	delete(f.byID, id)
	return nil
}

func (f *fakeGroups) AddMembers(ctx context.Context, id directory.GroupID, members []directory.MemberRef, rev directory.Revision) (directory.MembershipSummary, error) {
	return f.mutate(id, members, rev, true, false)
}

func (f *fakeGroups) RemoveMembers(ctx context.Context, id directory.GroupID, members []directory.MemberRef, rev directory.Revision) (directory.MembershipSummary, error) {
	return f.mutate(id, members, rev, false, false)
}

func (f *fakeGroups) ReplaceMembers(ctx context.Context, id directory.GroupID, members []directory.MemberRef, rev directory.Revision) (directory.MembershipSummary, error) {
	return f.mutate(id, members, rev, false, true)
}

func (f *fakeGroups) mutate(id directory.GroupID, members []directory.MemberRef, rev directory.Revision, add, replace bool) (directory.MembershipSummary, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	g, ok := f.byID[id]
	if !ok {
		return directory.MembershipSummary{}, directory.Error("entry", directory.FieldNotFound, "directory entry not found")
	}
	if rev != "" && g.Revision != rev {
		return directory.MembershipSummary{}, directory.Error("revision", directory.FieldConflict, "directory entry revision does not match")
	}
	have := map[string]directory.MemberRef{}
	for _, m := range g.Members {
		have[m.ID] = m
	}
	sum := directory.MembershipSummary{}
	if replace {
		want := map[string]directory.MemberRef{}
		for _, m := range members {
			want[m.ID] = m
			if _, ok := have[m.ID]; ok {
				sum.Unchanged = append(sum.Unchanged, m)
			} else {
				sum.Added = append(sum.Added, m)
			}
		}
		for _, m := range g.Members {
			if _, ok := want[m.ID]; !ok {
				sum.Removed = append(sum.Removed, m)
			}
		}
		g.Members = members
	} else if add {
		for _, m := range members {
			if _, ok := have[m.ID]; ok {
				sum.Unchanged = append(sum.Unchanged, m)
			} else {
				sum.Added = append(sum.Added, m)
				g.Members = append(g.Members, m)
			}
		}
	} else {
		drop := map[string]struct{}{}
		for _, m := range members {
			if _, ok := have[m.ID]; ok {
				sum.Removed = append(sum.Removed, m)
				drop[m.ID] = struct{}{}
			} else {
				sum.Unchanged = append(sum.Unchanged, m)
			}
		}
		var keep []directory.MemberRef
		for _, m := range g.Members {
			if _, ok := drop[m.ID]; !ok {
				keep = append(keep, m)
			}
		}
		g.Members = keep
	}
	g.Revision = directory.RevisionOfGroup(g)
	f.byID[id] = g
	sum.Revision = g.Revision
	return sum, nil
}

type fakeSearch struct {
	page directory.SearchPage
	err  error
}

func (f fakeSearch) Search(context.Context, directory.SearchQuery) (directory.SearchPage, error) {
	return f.page, f.err
}

type fakeBind struct {
	res directory.BindTestResult
	err error
}

func (f fakeBind) BindTest(context.Context, string, observability.Secret, directory.Transport) (directory.BindTestResult, error) {
	return f.res, f.err
}

type fakeSchema struct {
	dse directory.RootDSE
	sch directory.Schema
	err error
}

func (f fakeSchema) RootDSE(context.Context) (directory.RootDSE, error) { return f.dse, f.err }
func (f fakeSchema) Schema(context.Context) (directory.Schema, error)   { return f.sch, f.err }

type fakeCaps struct {
	caps directory.Capabilities
	err  error
}

func (f fakeCaps) Capabilities(context.Context) (directory.Capabilities, error) {
	return f.caps, f.err
}

type fakeMarker struct {
	m   directory.BaselineMarker
	err error
}

func (f fakeMarker) ReadMarker(context.Context) (directory.BaselineMarker, error) {
	return f.m, f.err
}

type blockingGate struct{ err error }

func (g blockingGate) Allow(context.Context) error     { return g.err }
func (g blockingGate) AllowRead(context.Context) error { return nil }

type unusedReset struct{}

func (unusedReset) Inventory(context.Context) (directory.ManagedInventory, error) {
	return directory.ManagedInventory{}, nil
}
func (unusedReset) DeleteManaged(context.Context, string) error                      { return nil }
func (unusedReset) Export(context.Context, io.Writer, directory.ExportOptions) error { return nil }

func kvFromMap(in map[string]string) []directory.AttrKV {
	var out []directory.AttrKV
	for k, v := range in {
		out = append(out, directory.AttrKV{Name: k, Value: v})
	}
	return out
}

func writer() Principal {
	return Principal{Kind: KindToken, ID: "admin", Scopes: directory.ScopeSet{
		"directory:read", "directory:write", "directory:password", "schema:read",
	}}
}

func reader() Principal {
	return Principal{Kind: KindToken, ID: "reader", Scopes: directory.ScopeSet{"directory:read"}}
}

func hasSecret(s string, secrets ...string) bool {
	for _, sec := range secrets {
		if sec != "" && strings.Contains(s, sec) {
			return true
		}
	}
	return false
}
