package api

import (
	"context"
	"strings"
	"sync"

	"github.com/hilather/go-lab-ldap-mcp/internal/directory"
	"github.com/hilather/go-lab-ldap-mcp/internal/observability"
)

// In-memory directory repos for handler tests. They implement the
// repository contracts; handlers still go through internal/app.

type memUsers struct {
	mu        sync.Mutex
	byID      map[directory.UserID]directory.User
	passwords map[directory.UserID]string
}

func newMemUsers() *memUsers {
	return &memUsers{byID: map[directory.UserID]directory.User{}, passwords: map[directory.UserID]string{}}
}

func (m *memUsers) put(u directory.User) directory.User {
	if u.UID == "" {
		u.UID = u.ID
	}
	if u.ObjectClasses == nil {
		u.ObjectClasses = []string{}
	}
	if u.Attributes == nil {
		u.Attributes = []directory.AttrKV{}
	}
	u.Revision = directory.RevisionOfUser(u)
	m.byID[directory.UserID(u.ID)] = u
	return u
}

func (m *memUsers) List(_ context.Context, q directory.UserListQuery) (directory.UserPage, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	var items []directory.User
	needle := strings.ToLower(q.Q)
	for _, u := range m.byID {
		if needle != "" && !strings.Contains(strings.ToLower(u.ID), needle) && !strings.Contains(strings.ToLower(u.UID), needle) {
			continue
		}
		items = append(items, u)
	}
	return directory.UserPage{Items: items}, nil
}

func (m *memUsers) Get(_ context.Context, id directory.UserID) (directory.User, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	u, ok := m.byID[id]
	if !ok {
		return directory.User{}, directory.Error("entry", directory.FieldNotFound, "directory entry not found")
	}
	return u, nil
}

func (m *memUsers) Add(_ context.Context, spec directory.UserSpec) (directory.User, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	id := directory.UserID(spec.ID)
	if _, ok := m.byID[id]; ok {
		return directory.User{}, directory.Error("entry", directory.FieldConflict, "directory entry already exists")
	}
	u := directory.User{ID: spec.ID, UID: spec.UID, Enabled: true, DN: "uid=" + spec.ID + ",ou=people,dc=example,dc=test"}
	if u.UID == "" {
		u.UID = spec.ID
	}
	if spec.Enabled != nil {
		u.Enabled = *spec.Enabled
	}
	for k, v := range spec.Attributes {
		u.Attributes = append(u.Attributes, directory.AttrKV{Name: k, Value: v})
	}
	u = m.put(u)
	m.passwords[id] = spec.Password.Reveal()
	return u, nil
}

func (m *memUsers) Modify(_ context.Context, id directory.UserID, patch directory.UserPatch, rev directory.Revision) (directory.User, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	u, err := m.match(id, rev)
	if err != nil {
		return directory.User{}, err
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
	u.Attributes = nil
	for k, v := range attrs {
		u.Attributes = append(u.Attributes, directory.AttrKV{Name: k, Value: v})
	}
	return m.put(u), nil
}

func (m *memUsers) SetEnabled(_ context.Context, id directory.UserID, enabled bool, rev directory.Revision) (directory.User, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	u, err := m.match(id, rev)
	if err != nil {
		return directory.User{}, err
	}
	u.Enabled = enabled
	return m.put(u), nil
}

func (m *memUsers) Delete(_ context.Context, id directory.UserID, rev directory.Revision) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, err := m.match(id, rev); err != nil {
		return err
	}
	delete(m.byID, id)
	delete(m.passwords, id)
	return nil
}

func (m *memUsers) SetPassword(_ context.Context, id directory.UserID, password observability.Secret, rev directory.Revision) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, err := m.match(id, rev); err != nil {
		return err
	}
	m.passwords[id] = password.Reveal()
	return nil
}

func (m *memUsers) match(id directory.UserID, rev directory.Revision) (directory.User, error) {
	u, ok := m.byID[id]
	if !ok {
		return directory.User{}, directory.Error("entry", directory.FieldNotFound, "directory entry not found")
	}
	if rev != "" && u.Revision != rev {
		return directory.User{}, directory.Error("revision", directory.FieldConflict, "directory entry revision does not match")
	}
	return u, nil
}

type memGroups struct {
	mu   sync.Mutex
	byID map[directory.GroupID]directory.Group
}

func newMemGroups() *memGroups {
	return &memGroups{byID: map[directory.GroupID]directory.Group{}}
}

func (m *memGroups) put(g directory.Group) directory.Group {
	if g.DN == "" {
		g.DN = "cn=" + g.ID + ",ou=groups,dc=example,dc=test"
	}
	if g.Members == nil {
		g.Members = []directory.MemberRef{}
	}
	g.Revision = directory.RevisionOfGroup(g)
	m.byID[directory.GroupID(g.ID)] = g
	return g
}

func (m *memGroups) List(context.Context, directory.GroupListQuery) (directory.GroupPage, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	var items []directory.Group
	for _, g := range m.byID {
		items = append(items, g)
	}
	return directory.GroupPage{Items: items}, nil
}

func (m *memGroups) Get(_ context.Context, id directory.GroupID) (directory.Group, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	g, ok := m.byID[id]
	if !ok {
		return directory.Group{}, directory.Error("entry", directory.FieldNotFound, "directory entry not found")
	}
	return g, nil
}

func (m *memGroups) Add(_ context.Context, spec directory.GroupSpec) (directory.Group, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, ok := m.byID[directory.GroupID(spec.ID)]; ok {
		return directory.Group{}, directory.Error("entry", directory.FieldConflict, "directory entry already exists")
	}
	return m.put(directory.Group{ID: spec.ID, Members: spec.Members}), nil
}

func (m *memGroups) Delete(_ context.Context, id directory.GroupID, rev directory.Revision) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, err := m.match(id, rev); err != nil {
		return err
	}
	delete(m.byID, id)
	return nil
}

func (m *memGroups) AddMembers(_ context.Context, id directory.GroupID, members []directory.MemberRef, rev directory.Revision) (directory.MembershipSummary, error) {
	return m.mutate(id, members, rev, true, false)
}

func (m *memGroups) RemoveMembers(_ context.Context, id directory.GroupID, members []directory.MemberRef, rev directory.Revision) (directory.MembershipSummary, error) {
	return m.mutate(id, members, rev, false, false)
}

func (m *memGroups) ReplaceMembers(_ context.Context, id directory.GroupID, members []directory.MemberRef, rev directory.Revision) (directory.MembershipSummary, error) {
	return m.mutate(id, members, rev, false, true)
}

func (m *memGroups) mutate(id directory.GroupID, members []directory.MemberRef, rev directory.Revision, add, replace bool) (directory.MembershipSummary, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	g, err := m.match(id, rev)
	if err != nil {
		return directory.MembershipSummary{}, err
	}
	have := map[string]directory.MemberRef{}
	for _, mem := range g.Members {
		have[mem.ID] = mem
	}
	sum := directory.MembershipSummary{}
	if replace {
		want := map[string]directory.MemberRef{}
		for _, mem := range members {
			want[mem.ID] = mem
			if _, ok := have[mem.ID]; ok {
				sum.Unchanged = append(sum.Unchanged, mem)
			} else {
				sum.Added = append(sum.Added, mem)
			}
		}
		for _, mem := range g.Members {
			if _, ok := want[mem.ID]; !ok {
				sum.Removed = append(sum.Removed, mem)
			}
		}
		g.Members = members
	} else if add {
		for _, mem := range members {
			if _, ok := have[mem.ID]; ok {
				sum.Unchanged = append(sum.Unchanged, mem)
			} else {
				sum.Added = append(sum.Added, mem)
				g.Members = append(g.Members, mem)
			}
		}
	} else {
		drop := map[string]struct{}{}
		for _, mem := range members {
			if _, ok := have[mem.ID]; ok {
				sum.Removed = append(sum.Removed, mem)
				drop[mem.ID] = struct{}{}
			} else {
				sum.Unchanged = append(sum.Unchanged, mem)
			}
		}
		var keep []directory.MemberRef
		for _, mem := range g.Members {
			if _, ok := drop[mem.ID]; !ok {
				keep = append(keep, mem)
			}
		}
		g.Members = keep
	}
	g = m.put(g)
	sum.Revision = g.Revision
	return sum, nil
}

type memSearch struct {
	mu   sync.Mutex
	last directory.SearchQuery
	page directory.SearchPage
	err  error
}

func newMemSearch() *memSearch { return &memSearch{} }

func (m *memSearch) Search(_ context.Context, q directory.SearchQuery) (directory.SearchPage, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.last = q
	if m.err != nil {
		return directory.SearchPage{}, m.err
	}
	return m.page, nil
}

type memBind struct {
	mu     sync.Mutex
	lastID string
	lastPW string
	lastT  directory.Transport
	res    directory.BindTestResult
	err    error
}

func newMemBind() *memBind {
	return &memBind{res: directory.BindTestResult{Outcome: directory.BindOutcomeInvalidCredentials}}
}

func (m *memBind) BindTest(_ context.Context, identity string, password observability.Secret, t directory.Transport) (directory.BindTestResult, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.lastID = identity
	m.lastPW = password.Reveal()
	m.lastT = t
	if m.err != nil {
		return m.res, m.err
	}
	return m.res, nil
}

type memSchema struct {
	mu  sync.Mutex
	dse directory.RootDSE
	sch directory.Schema
	err error
}

func newMemSchema() *memSchema {
	return &memSchema{
		dse: directory.RootDSE{
			NamingContexts:    []string{"dc=example,dc=test"},
			VendorName:        "389 Project",
			VendorVersion:     "3.1.2",
			SupportedControls: []string{"1.2.840.113556.1.4.473"},
			SupportedSASL:     []string{"EXTERNAL"},
		},
		sch: directory.Schema{
			ObjectClasses: []directory.ObjectClass{{
				Name: "inetOrgPerson",
				OID:  "2.16.840.1.113730.3.2.2",
				Kind: "structural",
				Must: []string{"sn", "cn"},
				May:  []string{"uid", "mail"},
				Sup:  []string{"organizationalPerson"},
			}},
			Attributes: []directory.AttributeType{
				{Name: "uid", OID: "0.9.2342.19200300.100.1.1", Syntax: "1.3.6.1.4.1.1466.115.121.1.15", SingleValue: true},
				{Name: "nsslapd-rootpw", OID: "2.16.840.1.113730.3.1.211", Syntax: "1.3.6.1.4.1.1466.115.121.1.15"},
				{Name: "userPassword", OID: "2.5.4.35", Syntax: "1.3.6.1.4.1.1466.115.121.1.40"},
			},
		},
	}
}

func (m *memSchema) RootDSE(context.Context) (directory.RootDSE, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.dse, m.err
}

func (m *memSchema) Schema(context.Context) (directory.Schema, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.sch, m.err
}

func (m *memGroups) match(id directory.GroupID, rev directory.Revision) (directory.Group, error) {
	g, ok := m.byID[id]
	if !ok {
		return directory.Group{}, directory.Error("entry", directory.FieldNotFound, "directory entry not found")
	}
	if rev != "" && g.Revision != rev {
		return directory.Group{}, directory.Error("revision", directory.FieldConflict, "directory entry revision does not match")
	}
	return g, nil
}
