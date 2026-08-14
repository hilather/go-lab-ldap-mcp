package ds389

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/go-ldap/ldap/v3"

	"github.com/hilather/go-lab-ldap-mcp/internal/apperr"
	"github.com/hilather/go-lab-ldap-mcp/internal/bootstrap"
	"github.com/hilather/go-lab-ldap-mcp/internal/config"
	"github.com/hilather/go-lab-ldap-mcp/internal/config/v1alpha1"
	"github.com/hilather/go-lab-ldap-mcp/internal/observability"
)

type seedMem struct {
	entries          map[string]*ldap.Entry
	adds, mods, dels []string
	failPWAfterAdd   bool
	delErr           error
	binds            []string
}

func (m *seedMem) Search(req *ldap.SearchRequest) (*ldap.SearchResult, error) {
	switch req.Scope {
	case ldap.ScopeBaseObject:
		e, ok := m.entries[strings.ToLower(req.BaseDN)]
		if !ok {
			return nil, ldap.NewError(ldap.LDAPResultNoSuchObject, errors.New("no such object"))
		}
		return &ldap.SearchResult{Entries: []*ldap.Entry{cloneEntry(e)}}, nil
	case ldap.ScopeSingleLevel:
		var out []*ldap.Entry
		for _, e := range m.entries {
			if isDirectChild(e.DN, req.BaseDN) {
				out = append(out, cloneEntry(e))
			}
		}
		return &ldap.SearchResult{Entries: out}, nil
	default:
		return &ldap.SearchResult{}, nil
	}
}

func (m *seedMem) Add(req *ldap.AddRequest) error {
	m.adds = append(m.adds, req.DN)
	key := strings.ToLower(req.DN)
	if _, ok := m.entries[key]; ok {
		return ldap.NewError(ldap.LDAPResultEntryAlreadyExists, errors.New("exists"))
	}
	if m.entries == nil {
		m.entries = map[string]*ldap.Entry{}
	}
	e := &ldap.Entry{DN: req.DN}
	for _, a := range req.Attributes {
		e.Attributes = append(e.Attributes, &ldap.EntryAttribute{Name: a.Type, Values: append([]string(nil), a.Vals...)})
	}
	m.entries[key] = e
	return nil
}

func (m *seedMem) Modify(req *ldap.ModifyRequest) error {
	m.mods = append(m.mods, req.DN)
	key := strings.ToLower(req.DN)
	e := m.entries[key]
	if m.failPWAfterAdd && e != nil && !hasValue(e, "userPassword", "") && justAdded(m, req.DN) {
		for _, ch := range req.Changes {
			if strings.EqualFold(ch.Modification.Type, "userPassword") {
				return ldap.NewError(ldap.LDAPResultUnwillingToPerform, errors.New("injected password fail"))
			}
		}
	}
	if e == nil {
		return ldap.NewError(ldap.LDAPResultNoSuchObject, errors.New("no such object"))
	}
	applyChanges(e, req.Changes)
	return nil
}

func (m *seedMem) Del(req *ldap.DelRequest) error {
	m.dels = append(m.dels, req.DN)
	if m.delErr != nil {
		return m.delErr
	}
	delete(m.entries, strings.ToLower(req.DN))
	return nil
}

func (m *seedMem) Bind(username, password string) error {
	m.binds = append(m.binds, username)
	return nil
}

func (m *seedMem) Close() error { return nil }

func justAdded(m *seedMem, dn string) bool {
	for _, a := range m.adds {
		if strings.EqualFold(a, dn) {
			return true
		}
	}
	return false
}

func cloneEntry(e *ldap.Entry) *ldap.Entry {
	out := &ldap.Entry{DN: e.DN}
	for _, a := range e.Attributes {
		out.Attributes = append(out.Attributes, &ldap.EntryAttribute{Name: a.Name, Values: append([]string(nil), a.Values...)})
	}
	return out
}

func applyChanges(e *ldap.Entry, changes []ldap.Change) {
	for _, ch := range changes {
		name := ch.Modification.Type
		switch ch.Operation {
		case ldap.ReplaceAttribute:
			setAttr(e, name, ch.Modification.Vals)
		case ldap.AddAttribute:
			cur := e.GetAttributeValues(name)
			setAttr(e, name, append(cur, ch.Modification.Vals...))
		case ldap.DeleteAttribute:
			if len(ch.Modification.Vals) == 0 {
				setAttr(e, name, nil)
				continue
			}
			drop := map[string]struct{}{}
			for _, v := range ch.Modification.Vals {
				drop[v] = struct{}{}
			}
			var next []string
			for _, v := range e.GetAttributeValues(name) {
				if _, ok := drop[v]; !ok {
					next = append(next, v)
				}
			}
			setAttr(e, name, next)
		}
	}
}

func setAttr(e *ldap.Entry, name string, vals []string) {
	var next []*ldap.EntryAttribute
	for _, a := range e.Attributes {
		if !strings.EqualFold(a.Name, name) {
			next = append(next, a)
		}
	}
	if len(vals) > 0 {
		next = append(next, &ldap.EntryAttribute{Name: name, Values: append([]string(nil), vals...)})
	}
	e.Attributes = next
}

func isDirectChild(child, parent string) bool {
	c, err := config.ParseDN(child)
	if err != nil {
		return false
	}
	p, err := config.ParseDN(parent)
	if err != nil {
		return false
	}
	if !c.IsDescendantOf(p) {
		return false
	}
	attr, val, ok := c.Leaf()
	if !ok {
		return false
	}
	rdn, err := config.BuildRDN(attr, val)
	if err != nil {
		return false
	}
	rest := strings.TrimPrefix(c.String(), rdn+",")
	pd, err := config.ParseDN(rest)
	return err == nil && pd.Equal(p)
}

func sampleSeedReq(write bool, mode string) bootstrap.SeedRequest {
	pw := config.ResolvedSecret{Value: observability.Secret("alice-seed-secret")}
	return bootstrap.SeedRequest{
		TreeRequest: bootstrap.TreeRequest{
			Suffix:     "dc=example,dc=test",
			PeopleDN:   "ou=people,dc=example,dc=test",
			GroupsDN:   "ou=groups,dc=example,dc=test",
			RuntimeDN:  "uid=rt,ou=people,dc=example,dc=test",
			DMPassword: observability.Secret("dm-secret"),
			Write:      write,
		},
		StartupMode: mode,
		Preserve:    []string{"uid=rt,ou=people,dc=example,dc=test", "ou=people,dc=example,dc=test", "ou=groups,dc=example,dc=test"},
		Users: []config.NormalizedUser{{
			ID:            "alice",
			UID:           "alice",
			DN:            "uid=alice,ou=people,dc=example,dc=test",
			Enabled:       true,
			Password:      &pw,
			ObjectClasses: config.RequiredUserObjectClasses(),
		}},
		Groups: []config.NormalizedGroup{{
			ID: "staff",
			DN: "cn=staff,ou=groups,dc=example,dc=test",
			Members: []config.MemberRef{{
				Kind: "user", ID: "alice", DN: "uid=alice,ou=people,dc=example,dc=test",
			}},
		}},
	}
}

func baseEntries() map[string]*ldap.Entry {
	return map[string]*ldap.Entry{
		"dc=example,dc=test":                  {DN: "dc=example,dc=test"},
		"ou=people,dc=example,dc=test":        {DN: "ou=people,dc=example,dc=test"},
		"ou=groups,dc=example,dc=test":        {DN: "ou=groups,dc=example,dc=test"},
		"uid=rt,ou=people,dc=example,dc=test": {DN: "uid=rt,ou=people,dc=example,dc=test", Attributes: []*ldap.EntryAttribute{{Name: "uid", Values: []string{"rt"}}, {Name: "sn", Values: []string{"runtime"}}}},
	}
}

func testSeedEngine(mem *seedMem) Engine {
	return Engine{
		TreeDial: func(context.Context, bootstrap.TreeRequest) (treeConn, error) { return mem, nil },
		SeedBind: func(context.Context, bootstrap.TreeRequest, string, string) error { return nil },
	}
}

func TestReconcileSeedCreatesUsersAndGroups(t *testing.T) {
	mem := &seedMem{entries: baseEntries()}
	res, err := testSeedEngine(mem).ReconcileSeed(t.Context(), sampleSeedReq(true, v1alpha1.StartupMerge))
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Created) != 2 {
		t.Fatalf("created = %v", res.Created)
	}
	alice := mem.entries["uid=alice,ou=people,dc=example,dc=test"]
	if alice == nil {
		t.Fatal("alice missing")
	}
	if !hasValue(alice, "sn", "alice") {
		t.Fatalf("default sn must be user ID, attrs=%v", alice.Attributes)
	}
	if hasValue(alice, "sn", "runtime") {
		t.Fatal("copied runtime sn onto seed user")
	}
	if !hasObjectClass(alice, "inetOrgPerson") || !hasObjectClass(alice, "person") {
		t.Fatalf("objectClass = %v", alice.GetAttributeValues("objectClass"))
	}
	if alice.GetAttributeValue("memberOf") != "" {
		t.Fatal("wrote memberOf")
	}
	staff := mem.entries["cn=staff,ou=groups,dc=example,dc=test"]
	if staff == nil || !hasValue(staff, "member", "uid=alice,ou=people,dc=example,dc=test") {
		t.Fatalf("staff members = %v", staff)
	}
	joined := strings.Join(mem.adds, " ")
	if strings.Contains(joined, "alice-seed-secret") || strings.Contains(joined, "dm-secret") {
		t.Fatalf("secret on add DN: %s", joined)
	}
}

func TestReconcileSeedSNOverrideAndLock(t *testing.T) {
	mem := &seedMem{entries: baseEntries()}
	req := sampleSeedReq(true, v1alpha1.StartupMerge)
	req.Users[0].Enabled = false
	req.Users[0].Attributes = []config.AttrKV{{Name: "sn", Value: "Smith"}, {Name: "description", Value: "lab user"}, {Name: "memberOf", Value: "cn=nope"}}
	_, err := testSeedEngine(mem).ReconcileSeed(t.Context(), req)
	if err != nil {
		t.Fatal(err)
	}
	alice := mem.entries["uid=alice,ou=people,dc=example,dc=test"]
	if !hasValue(alice, "sn", "Smith") || !hasValue(alice, "description", "lab user") {
		t.Fatalf("attrs = %v", alice.Attributes)
	}
	if !accountLocked(alice) {
		t.Fatal("disabled user missing nsAccountLock")
	}
	if alice.GetAttributeValue("memberOf") != "" {
		t.Fatal("wrote forbidden memberOf")
	}
}

func TestReconcileSeedIdempotentMatch(t *testing.T) {
	mem := &seedMem{entries: baseEntries()}
	eng := testSeedEngine(mem)
	req := sampleSeedReq(true, v1alpha1.StartupMerge)
	if _, err := eng.ReconcileSeed(t.Context(), req); err != nil {
		t.Fatal(err)
	}
	adds := len(mem.adds)
	res, err := eng.ReconcileSeed(t.Context(), req)
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Created) != 0 || len(res.Matched) != 2 {
		t.Fatalf("res=%+v", res)
	}
	if len(mem.adds) != adds {
		t.Fatalf("re-apply added: %v", mem.adds)
	}
}

func TestReconcileSeedValidateNoWrite(t *testing.T) {
	mem := &seedMem{entries: baseEntries()}
	res, err := testSeedEngine(mem).ReconcileSeed(t.Context(), sampleSeedReq(false, v1alpha1.StartupValidate))
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Matched) != 0 || len(mem.adds) != 0 || len(mem.mods) != 0 || len(mem.dels) != 0 {
		t.Fatalf("validate wrote or matched missing entries: res=%+v adds=%v mods=%v dels=%v", res, mem.adds, mem.mods, mem.dels)
	}
}

func TestReconcileSeedMergeKeepsExtra(t *testing.T) {
	mem := &seedMem{entries: baseEntries()}
	mem.entries["uid=extra,ou=people,dc=example,dc=test"] = &ldap.Entry{DN: "uid=extra,ou=people,dc=example,dc=test"}
	_, err := testSeedEngine(mem).ReconcileSeed(t.Context(), sampleSeedReq(true, v1alpha1.StartupMerge))
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := mem.entries["uid=extra,ou=people,dc=example,dc=test"]; !ok {
		t.Fatal("merge deleted extra user")
	}
}

func TestReconcileSeedResetDeletesExtraPreservesRuntime(t *testing.T) {
	mem := &seedMem{entries: baseEntries()}
	mem.entries["uid=extra,ou=people,dc=example,dc=test"] = &ldap.Entry{DN: "uid=extra,ou=people,dc=example,dc=test"}
	mem.entries["cn=temp,ou=groups,dc=example,dc=test"] = &ldap.Entry{
		DN: "cn=temp,ou=groups,dc=example,dc=test",
		Attributes: []*ldap.EntryAttribute{
			{Name: "member", Values: []string{"uid=extra,ou=people,dc=example,dc=test"}},
		},
	}
	res, err := testSeedEngine(mem).ReconcileSeed(t.Context(), sampleSeedReq(true, v1alpha1.StartupReset))
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := mem.entries["uid=extra,ou=people,dc=example,dc=test"]; ok {
		t.Fatal("reset left extra user")
	}
	if _, ok := mem.entries["cn=temp,ou=groups,dc=example,dc=test"]; ok {
		t.Fatal("reset left extra group")
	}
	if _, ok := mem.entries["uid=rt,ou=people,dc=example,dc=test"]; !ok {
		t.Fatal("reset deleted runtime account")
	}
	if len(res.Deleted) < 2 {
		t.Fatalf("deleted = %v", res.Deleted)
	}
}

func TestReconcileSeedPasswordFailureCompensates(t *testing.T) {
	mem := &seedMem{entries: baseEntries(), failPWAfterAdd: true}
	_, err := testSeedEngine(mem).ReconcileSeed(t.Context(), sampleSeedReq(true, v1alpha1.StartupMerge))
	if err == nil || !fieldHas(err, "phase.seed", "password_set") {
		t.Fatalf("%v", err)
	}
	apperr.Assert(t, err).Code(apperr.CodeBootstrap).FieldPath("phase.seed")
	if _, ok := mem.entries["uid=alice,ou=people,dc=example,dc=test"]; ok {
		t.Fatal("incomplete user left after password_set")
	}
	if len(mem.dels) == 0 {
		t.Fatal("expected compensation delete")
	}
	if strings.Contains(err.Error(), "alice-seed-secret") {
		t.Fatal("error leaked password")
	}
}

func TestReconcileSeedPasswordFailurePartial(t *testing.T) {
	mem := &seedMem{
		entries:        baseEntries(),
		failPWAfterAdd: true,
		delErr:         ldap.NewError(ldap.LDAPResultUnwillingToPerform, errors.New("injected del fail")),
	}
	_, err := testSeedEngine(mem).ReconcileSeed(t.Context(), sampleSeedReq(true, v1alpha1.StartupMerge))
	if err == nil || !fieldHas(err, "phase.seed", "partial") {
		t.Fatalf("%v", err)
	}
	if _, ok := mem.entries["uid=alice,ou=people,dc=example,dc=test"]; !ok {
		t.Fatal("expected leftover incomplete user on partial")
	}
}

func TestReconcileSeedBindsEnabledUsers(t *testing.T) {
	mem := &seedMem{entries: baseEntries()}
	var bound []string
	eng := Engine{
		TreeDial: func(context.Context, bootstrap.TreeRequest) (treeConn, error) { return mem, nil },
		SeedBind: func(_ context.Context, _ bootstrap.TreeRequest, dn, password string) error {
			if password == "alice-seed-secret" {
				bound = append(bound, dn)
			}
			if password == "alice-seed-secret" && strings.Contains(dn, "alice") {
				return nil
			}
			return errors.New("unexpected bind")
		},
	}
	if _, err := eng.ReconcileSeed(t.Context(), sampleSeedReq(true, v1alpha1.StartupMerge)); err != nil {
		t.Fatal(err)
	}
	if len(bound) != 1 {
		t.Fatalf("binds = %v", bound)
	}
}

func TestUserSNNeverRuntimeLiteral(t *testing.T) {
	u := config.NormalizedUser{ID: "bob", UID: "bob"}
	if userSN(u) == "runtime" {
		t.Fatal("default sn must not be runtime")
	}
	if userSN(u) != "bob" {
		t.Fatalf("sn = %q", userSN(u))
	}
}
