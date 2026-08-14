package mcpserver

import (
	"context"
	"encoding/json"
	"io"
	"strings"
	"sync"
	"time"

	"github.com/hilather/go-lab-ldap-mcp/internal/directory"
	"github.com/hilather/go-lab-ldap-mcp/internal/observability"
)

type fakeUsers struct {
	mu        sync.Mutex
	byID      map[directory.UserID]directory.User
	passwords map[directory.UserID]string
}

func newFakeUsers() *fakeUsers {
	return &fakeUsers{byID: map[directory.UserID]directory.User{}, passwords: map[directory.UserID]string{}}
}

func (f *fakeUsers) put(u directory.User) directory.User {
	if u.UID == "" {
		u.UID = u.ID
	}
	if u.DN == "" {
		u.DN = "uid=" + u.ID + ",ou=people,dc=example,dc=test"
	}
	if u.Revision == "" {
		u.Revision = directory.RevisionOfUser(u)
	}
	f.byID[directory.UserID(u.ID)] = u
	return u
}

func (f *fakeUsers) List(context.Context, directory.UserListQuery) (directory.UserPage, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	var items []directory.User
	for _, u := range f.byID {
		items = append(items, u)
	}
	return directory.UserPage{Items: items}, nil
}

func (f *fakeUsers) Get(_ context.Context, id directory.UserID) (directory.User, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
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
	u.DN = "uid=" + u.UID + ",ou=people,dc=example,dc=test"
	u.Revision = directory.RevisionOfUser(u)
	f.byID[id] = u
	f.passwords[id] = spec.Password.Reveal()
	return u, nil
}

func (f *fakeUsers) Modify(_ context.Context, id directory.UserID, patch directory.UserPatch, rev directory.Revision) (directory.User, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
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
	u, ok := f.byID[id]
	if !ok {
		return directory.Error("entry", directory.FieldNotFound, "directory entry not found")
	}
	if rev != "" && u.Revision != rev {
		return directory.Error("revision", directory.FieldConflict, "directory entry revision does not match")
	}
	delete(f.byID, id)
	delete(f.passwords, id)
	return nil
}

func (f *fakeUsers) SetPassword(_ context.Context, id directory.UserID, password observability.Secret, rev directory.Revision) error {
	f.mu.Lock()
	defer f.mu.Unlock()
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
	mu   sync.Mutex
	byID map[directory.GroupID]directory.Group
}

func newFakeGroups() *fakeGroups {
	return &fakeGroups{byID: map[directory.GroupID]directory.Group{}}
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
	g, ok := f.byID[id]
	if !ok {
		return directory.Group{}, directory.Error("entry", directory.FieldNotFound, "directory entry not found")
	}
	return g, nil
}

func (f *fakeGroups) Add(_ context.Context, spec directory.GroupSpec) (directory.Group, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if _, ok := f.byID[directory.GroupID(spec.ID)]; ok {
		return directory.Group{}, directory.Error("entry", directory.FieldConflict, "directory entry already exists")
	}
	g := directory.Group{ID: spec.ID, Members: spec.Members, DN: "cn=" + spec.ID + ",ou=groups,dc=example,dc=test"}
	g.Revision = directory.RevisionOfGroup(g)
	f.byID[directory.GroupID(spec.ID)] = g
	return g, nil
}

func (f *fakeGroups) Delete(_ context.Context, id directory.GroupID, rev directory.Revision) error {
	f.mu.Lock()
	defer f.mu.Unlock()
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

func (f *fakeGroups) AddMembers(_ context.Context, id directory.GroupID, members []directory.MemberRef, rev directory.Revision) (directory.MembershipSummary, error) {
	return f.mutate(id, members, rev, true, false)
}

func (f *fakeGroups) RemoveMembers(_ context.Context, id directory.GroupID, members []directory.MemberRef, rev directory.Revision) (directory.MembershipSummary, error) {
	return f.mutate(id, members, rev, false, false)
}

func (f *fakeGroups) ReplaceMembers(_ context.Context, id directory.GroupID, members []directory.MemberRef, rev directory.Revision) (directory.MembershipSummary, error) {
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

type fakeBind struct {
	mu       sync.Mutex
	calls    int
	open     int
	closed   int
	hang     chan struct{}
	saw      chan struct{}
	identity string
	password string
	outcome  string
}

func (f *fakeBind) BindTest(ctx context.Context, identity string, password observability.Secret, _ directory.Transport) (directory.BindTestResult, error) {
	f.mu.Lock()
	f.calls++
	f.open++
	f.mu.Unlock()
	defer func() {
		f.mu.Lock()
		f.open--
		f.closed++
		f.mu.Unlock()
	}()
	if f.saw != nil {
		select {
		case <-f.saw:
		default:
			close(f.saw)
		}
	}
	if f.hang != nil {
		select {
		case <-ctx.Done():
			close(f.hang)
			return directory.BindTestResult{}, ctx.Err()
		case <-time.After(8 * time.Second):
			return directory.BindTestResult{}, context.DeadlineExceeded
		}
	}
	if f.outcome != "" {
		return directory.BindTestResult{Outcome: f.outcome}, nil
	}
	if identity == f.identity && password.Reveal() == f.password {
		return directory.BindTestResult{Outcome: directory.BindOutcomeSuccess}, nil
	}
	// Unknown user and wrong password share this outcome.
	return directory.BindTestResult{Outcome: directory.BindOutcomeInvalidCredentials}, nil
}

type fakeResetDir struct {
	ldif    string
	limit   bool
	deleted []string
	exportN int
}

func (f *fakeResetDir) Inventory(context.Context) (directory.ManagedInventory, error) {
	return directory.ManagedInventory{
		Preserve: []string{
			"uid=rt,ou=people,dc=example,dc=test",
			"ou=people,dc=example,dc=test",
			"ou=groups,dc=example,dc=test",
			"cn=labldap-baseline,dc=example,dc=test",
		},
	}, nil
}

func (f *fakeResetDir) DeleteManaged(_ context.Context, dn string) error {
	f.deleted = append(f.deleted, dn)
	return nil
}

func (f *fakeResetDir) Export(_ context.Context, w io.Writer, opts directory.ExportOptions) error {
	f.exportN++
	if f.limit {
		return directory.ExportLimit("export.bytes", "export byte limit exceeded")
	}
	body := f.ldif
	if body == "" {
		body = "dn: dc=example,dc=test\nobjectClass: top\n\n"
	}
	if opts.MaxBytes > 0 && int64(len(body)) > opts.MaxBytes {
		return directory.ExportLimit("export.bytes", "export byte limit exceeded")
	}
	_, err := io.WriteString(w, body)
	return err
}

func kvFromMap(in map[string]string) []directory.AttrKV {
	if len(in) == 0 {
		return nil
	}
	out := make([]directory.AttrKV, 0, len(in))
	for k, v := range in {
		out = append(out, directory.AttrKV{Name: k, Value: v})
	}
	return out
}

func toolJSON(v any) string {
	raw, _ := json.Marshal(v)
	return string(raw)
}

func containsSecret(s string, secrets ...string) bool {
	for _, sec := range secrets {
		if sec != "" && strings.Contains(s, sec) {
			return true
		}
	}
	return false
}
