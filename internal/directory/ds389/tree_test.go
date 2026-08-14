package ds389

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/go-ldap/ldap/v3"

	"github.com/hilather/go-lab-ldap-mcp/internal/apperr"
	"github.com/hilather/go-lab-ldap-mcp/internal/bootstrap"
	"github.com/hilather/go-lab-ldap-mcp/internal/observability"
)

type memTree struct {
	entries map[string]struct{}
	adds    []string
	mods    []string
	binds   []string
	addErr  error
}

func (m *memTree) Search(req *ldap.SearchRequest) (*ldap.SearchResult, error) {
	if _, ok := m.entries[strings.ToLower(req.BaseDN)]; !ok {
		return nil, ldap.NewError(ldap.LDAPResultNoSuchObject, errors.New("no such object"))
	}
	return &ldap.SearchResult{Entries: []*ldap.Entry{{DN: req.BaseDN}}}, nil
}

func (m *memTree) Add(req *ldap.AddRequest) error {
	m.adds = append(m.adds, req.DN)
	if m.addErr != nil {
		return m.addErr
	}
	if m.entries == nil {
		m.entries = map[string]struct{}{}
	}
	m.entries[strings.ToLower(req.DN)] = struct{}{}
	return nil
}

func (m *memTree) Modify(req *ldap.ModifyRequest) error {
	m.mods = append(m.mods, req.DN)
	return nil
}

func (m *memTree) Del(req *ldap.DelRequest) error {
	delete(m.entries, strings.ToLower(req.DN))
	return nil
}

func (m *memTree) Bind(username, password string) error {
	m.binds = append(m.binds, username)
	return nil
}

func (m *memTree) Close() error { return nil }

func sampleTreeReq(write bool) bootstrap.TreeRequest {
	return bootstrap.TreeRequest{
		Suffix:          "dc=example,dc=test",
		PeopleDN:        "ou=people,dc=example,dc=test",
		GroupsDN:        "ou=groups,dc=example,dc=test",
		RuntimeDN:       "uid=rt,ou=people,dc=example,dc=test",
		RuntimePassword: observability.Secret("runtime-secret"),
		DMPassword:      observability.Secret("dm-secret"),
		Write:           write,
	}
}

func TestReconcileTreeCreatesParentsAndAccount(t *testing.T) {
	mem := &memTree{entries: map[string]struct{}{
		"dc=example,dc=test": {},
	}}
	eng := Engine{
		TreeDial:    func(context.Context, bootstrap.TreeRequest) (treeConn, error) { return mem, nil },
		RuntimeBind: func(context.Context, bootstrap.TreeRequest) error { return nil },
	}
	res, err := eng.ReconcileTree(t.Context(), sampleTreeReq(true))
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Created) != 3 {
		t.Fatalf("created = %v", res.Created)
	}
	joined := strings.Join(mem.adds, " ")
	if !strings.Contains(joined, "ou=people") || !strings.Contains(joined, "uid=rt") {
		t.Fatalf("adds = %v", mem.adds)
	}
	for _, a := range mem.adds {
		if strings.Contains(a, "runtime-secret") || strings.Contains(a, "dm-secret") {
			t.Fatalf("secret on add DN: %s", a)
		}
	}
}

func TestReconcileTreeIdempotentMatch(t *testing.T) {
	req := sampleTreeReq(true)
	mem := &memTree{entries: map[string]struct{}{
		strings.ToLower(req.Suffix):    {},
		strings.ToLower(req.PeopleDN):  {},
		strings.ToLower(req.GroupsDN):  {},
		strings.ToLower(req.RuntimeDN): {},
	}}
	eng := Engine{
		TreeDial:    func(context.Context, bootstrap.TreeRequest) (treeConn, error) { return mem, nil },
		RuntimeBind: func(context.Context, bootstrap.TreeRequest) error { return nil },
	}
	res, err := eng.ReconcileTree(t.Context(), req)
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Created) != 0 || len(res.Matched) != 4 {
		t.Fatalf("res=%+v adds=%v", res, mem.adds)
	}
	if len(mem.mods) != 1 {
		t.Fatalf("expected password replace on match, mods=%v", mem.mods)
	}
}

func TestReconcileTreeValidateMissingParent(t *testing.T) {
	eng := Engine{
		TreeDial: func(context.Context, bootstrap.TreeRequest) (treeConn, error) {
			return &memTree{}, nil
		},
	}
	_, err := eng.ReconcileTree(t.Context(), sampleTreeReq(false))
	if err == nil || !fieldHas(err, "phase.tree", "parent_failed") {
		t.Fatalf("%v", err)
	}
	apperr.Assert(t, err).Code(apperr.CodeBootstrap).FieldPath("phase.tree")
}

func TestReconcileTreeAccountBind(t *testing.T) {
	req := sampleTreeReq(false)
	mem := &memTree{entries: map[string]struct{}{
		strings.ToLower(req.Suffix):   {},
		strings.ToLower(req.PeopleDN): {},
		strings.ToLower(req.GroupsDN): {},
	}}
	eng := Engine{
		TreeDial: func(context.Context, bootstrap.TreeRequest) (treeConn, error) { return mem, nil },
	}
	_, err := eng.ReconcileTree(t.Context(), req)
	if err == nil || !fieldHas(err, "phase.tree", "account_bind") {
		t.Fatalf("%v", err)
	}
}

func TestReconcileTreeValidateNoAdd(t *testing.T) {
	req := sampleTreeReq(false)
	mem := &memTree{entries: map[string]struct{}{
		strings.ToLower(req.Suffix):    {},
		strings.ToLower(req.PeopleDN):  {},
		strings.ToLower(req.GroupsDN):  {},
		strings.ToLower(req.RuntimeDN): {},
	}}
	eng := Engine{
		TreeDial:    func(context.Context, bootstrap.TreeRequest) (treeConn, error) { return mem, nil },
		RuntimeBind: func(context.Context, bootstrap.TreeRequest) error { return nil },
	}
	if _, err := eng.ReconcileTree(t.Context(), req); err != nil {
		t.Fatal(err)
	}
	if len(mem.adds) != 0 || len(mem.mods) != 0 {
		t.Fatalf("validate wrote adds=%v mods=%v", mem.adds, mem.mods)
	}
}

func TestLeafAVUnescapesSpecials(t *testing.T) {
	attr, value, err := leafAV(`uid=a\+b\,c,ou=people,dc=example,dc=test`)
	if err != nil {
		t.Fatal(err)
	}
	if attr != "uid" || value != "a+b,c" {
		t.Fatalf("leaf = %q %q", attr, value)
	}
}

func TestTreeDialTargetStartTLS(t *testing.T) {
	url, mode := treeDialTarget(bootstrap.TreeRequest{StartTLS: true, LDAPAddr: "127.0.0.1:3389"})
	if mode != "starttls" || !strings.HasPrefix(url, "ldap://") {
		t.Fatalf("url=%s mode=%s", url, mode)
	}
	url, mode = treeDialTarget(bootstrap.TreeRequest{UseLDAPS: true, LDAPSAddr: "127.0.0.1:3636"})
	if mode != "ldaps" {
		t.Fatalf("ldaps url=%s mode=%s", url, mode)
	}
	url, mode = treeDialTarget(bootstrap.TreeRequest{LDAPURL: "ldap://127.0.0.1:3389", StartTLS: true})
	if mode != "starttls" {
		t.Fatalf("explicit starttls url=%s mode=%s", url, mode)
	}
}

func TestReconcileTreeRuntimeBindFailure(t *testing.T) {
	req := sampleTreeReq(true)
	mem := &memTree{entries: map[string]struct{}{strings.ToLower(req.Suffix): {}}}
	eng := Engine{
		TreeDial: func(context.Context, bootstrap.TreeRequest) (treeConn, error) { return mem, nil },
		RuntimeBind: func(context.Context, bootstrap.TreeRequest) error {
			return errors.New("invalid credentials")
		},
	}
	_, err := eng.ReconcileTree(t.Context(), req)
	if err == nil || !fieldHas(err, "phase.tree", "account_bind") {
		t.Fatalf("%v", err)
	}
}
