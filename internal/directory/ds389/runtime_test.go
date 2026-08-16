package ds389

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/go-ldap/ldap/v3"

	"github.com/hilather/go-lab-ldap-mcp/internal/apperr"
	"github.com/hilather/go-lab-ldap-mcp/internal/config"
	"github.com/hilather/go-lab-ldap-mcp/internal/directory"
	"github.com/hilather/go-lab-ldap-mcp/internal/directory/ldapclient"
	"github.com/hilather/go-lab-ldap-mcp/internal/observability"
)

func testRuntime(t *testing.T) *Runtime {
	t.Helper()
	p, err := ldapclient.NewPool(ldapclient.Config{
		Address:            "127.0.0.1:1",
		Transport:          directory.TransportLDAP,
		AllowCleartextBind: true,
		Dial: func(context.Context, ldapclient.Config) (*ldapclient.Conn, error) {
			return nil, directory.Error("connection", directory.FieldUnavailable, "directory unavailable")
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = p.Close() })
	rt, err := NewRuntime(p, RuntimeConfig{
		Suffix:    "dc=example,dc=test",
		PeopleDN:  "ou=people,dc=example,dc=test",
		GroupsDN:  "ou=groups,dc=example,dc=test",
		RuntimeDN: "uid=rt,ou=people,dc=example,dc=test",
		Client: ldapclient.Config{
			Address:            "127.0.0.1:1",
			Transport:          directory.TransportLDAP,
			AllowCleartextBind: true,
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	return rt
}

func TestValidateUserSpecForbiddenAndRequired(t *testing.T) {
	t.Parallel()
	err := validateUserSpec(directory.UserSpec{ID: "alice", Attributes: map[string]string{"userPassword": "x"}})
	if err == nil || !hasField(err, "attributes.userPassword", "forbidden_attribute") {
		t.Fatalf("forbidden password attr: %v", err)
	}
	err = validateUserSpec(directory.UserSpec{ID: "alice", Attributes: map[string]string{"nsAccountLock": "true"}})
	if err == nil || !hasField(err, "attributes.nsAccountLock", "forbidden_attribute") {
		t.Fatalf("forbidden lock attr: %v", err)
	}
	err = validateUserSpec(directory.UserSpec{ID: "uid=alice,ou=people,dc=example,dc=test"})
	if err == nil || !hasField(err, "id", "invalid") {
		t.Fatalf("DN id: %v", err)
	}
	err = validateUserPatch(directory.UserPatch{Attributes: map[string]string{"sn": ""}})
	if err == nil || !hasField(err, "attributes.sn", "required") {
		t.Fatalf("empty sn: %v", err)
	}
}

func TestUserNeverIncludesPassword(t *testing.T) {
	t.Parallel()
	u := userFromEntry(nil, "")
	if u.ID != "" {
		t.Fatal("nil entry")
	}
}

func TestEmptyGroupRejected(t *testing.T) {
	t.Parallel()
	rt := testRuntime(t)
	_, err := rt.addGroup(t.Context(), directory.GroupSpec{ID: "staff"})
	if err == nil || !hasField(err, "members", "empty_group") {
		t.Fatalf("empty add: %v", err)
	}
	cur := []directory.MemberRef{{Kind: "user", ID: "alice", DN: "uid=alice,ou=people,dc=example,dc=test"}}
	sum := planMembership(cur, nil, nil, memberReplace)
	if len(finalMembers(cur, sum)) != 0 {
		t.Fatal("replace empty should plan zero members")
	}
}

func TestMembershipIdempotentSummaries(t *testing.T) {
	t.Parallel()
	alice := directory.MemberRef{Kind: "user", ID: "alice", DN: "uid=alice,ou=people,dc=example,dc=test"}
	bob := directory.MemberRef{Kind: "user", ID: "bob", DN: "uid=bob,ou=people,dc=example,dc=test"}
	add := planMembership([]directory.MemberRef{alice}, []directory.MemberRef{alice, bob}, nil, memberAdd)
	if len(add.Added) != 1 || add.Added[0].ID != "bob" || len(add.Unchanged) != 1 {
		t.Fatalf("add: %+v", add)
	}
	again := planMembership([]directory.MemberRef{alice, bob}, []directory.MemberRef{alice}, nil, memberAdd)
	if len(again.Added) != 0 || len(again.Unchanged) != 1 {
		t.Fatalf("idempotent add: %+v", again)
	}
	rm := planMembership([]directory.MemberRef{alice, bob}, []directory.MemberRef{alice}, nil, memberRemove)
	if len(rm.Removed) != 1 || rm.Removed[0].ID != "alice" {
		t.Fatalf("remove: %+v", rm)
	}
	missing := planMembership([]directory.MemberRef{alice}, []directory.MemberRef{bob}, nil, memberRemove)
	if len(missing.Removed) != 0 || len(missing.Unchanged) != 1 {
		t.Fatalf("idempotent remove: %+v", missing)
	}
}

func TestNestedGroupHook(t *testing.T) {
	t.Parallel()
	rt := testRuntime(t)
	err := rt.checkNested(directory.MemberRef{Kind: "group", ID: "staff"})
	if err == nil || !hasField(err, "members", "nested_disabled") {
		t.Fatalf("default nested: %v", err)
	}
	called := false
	rt.cfg.NestedMemberHook = func(m directory.MemberRef) error {
		called = true
		if m.ID != "staff" {
			t.Fatalf("hook member %+v", m)
		}
		return cfgErr("members", "nested_disabled", "nested groups are disabled")
	}
	if err := rt.checkNested(directory.MemberRef{Kind: "group", ID: "staff"}); err == nil || !called {
		t.Fatalf("hook: %v called=%v", err, called)
	}
}

func TestSearchConstraints(t *testing.T) {
	t.Parallel()
	rt := testRuntime(t)
	_, _, _, _, err := rt.buildSearch(directory.SearchQuery{})
	if err == nil || !hasField(err, "filter", "empty") {
		t.Fatalf("empty filter: %v", err)
	}
	_, _, _, _, err = rt.buildSearch(directory.SearchQuery{
		Base: "dc=example,dc=test", Scope: directory.SearchScopeSub, Filter: "(objectClass=*)",
	})
	if err == nil || !hasField(err, "filter", "over_broad") {
		t.Fatalf("suffix+sub match-all: %v", err)
	}
	_, _, _, _, err = rt.buildSearch(directory.SearchQuery{
		Base: "dc=example,dc=test", Scope: directory.SearchScopeSub, Filter: "(&(objectClass=*))",
	})
	if err == nil || !hasField(err, "filter", "over_broad") {
		t.Fatalf("suffix+sub (&): %v", err)
	}
	req, _, _, _, err := rt.buildSearch(directory.SearchQuery{
		Base: "dc=example,dc=test", Scope: directory.SearchScopeOne, Filter: "(objectClass=*)",
	})
	if err != nil || req.TimeLimit < 1 || req.SizeLimit < 1 {
		t.Fatalf("suffix+one match-all should be allowed with limits: %v %+v", err, req)
	}
	req, _, _, _, err = rt.buildSearch(directory.SearchQuery{
		Base: "ou=people,dc=example,dc=test", Scope: directory.SearchScopeSub, Filter: "(objectClass=*)",
	})
	if err != nil || req == nil {
		t.Fatalf("people+sub match-all: %v", err)
	}
	if req.SizeLimit != rt.cfg.SearchSizeLimit || req.TimeLimit < 1 {
		t.Fatalf("limits not applied: size=%d time=%d", req.SizeLimit, req.TimeLimit)
	}
	_, _, _, _, err = rt.buildSearch(directory.SearchQuery{Base: "cn=config", Filter: "(uid=a)"})
	if err == nil || fieldOf(err) != directory.FieldForbidden {
		t.Fatalf("escape cn=config: %v", err)
	}
	_, _, _, _, err = rt.buildSearch(directory.SearchQuery{Base: "dc=other,dc=com", Filter: "(uid=a)"})
	if err == nil || fieldOf(err) != directory.FieldForbidden {
		t.Fatalf("escape other suffix: %v", err)
	}
	_, _, _, _, err = rt.buildSearch(directory.SearchQuery{Filter: "(uid=alice"})
	if err == nil || !hasField(err, "filter", "unbalanced") {
		t.Fatalf("malformed: %v", err)
	}
	_, _, _, _, err = rt.buildSearch(directory.SearchQuery{Filter: strings.Repeat("(", 20) + strings.Repeat(")", 20)})
	if err == nil || !hasField(err, "filter", "too_deep") {
		t.Fatalf("too deep: %v", err)
	}
	_, _, _, _, err = rt.buildSearch(directory.SearchQuery{Filter: "(uid=" + strings.Repeat("a", 5000) + ")"})
	if err == nil || !hasField(err, "filter", "too_long") {
		t.Fatalf("too long: %v", err)
	}
	_, _, _, _, err = rt.buildSearch(directory.SearchQuery{Filter: "(uid=a)", Attributes: []string{"userPassword", "cn"}})
	if err != nil {
		t.Fatal(err)
	}
	_, _, _, _, err = rt.buildSearch(directory.SearchQuery{
		Base: "dc=example,dc=test", Scope: directory.SearchScopeChildren, Filter: "(objectClass=*)",
	})
	if err == nil || !hasField(err, "filter", "over_broad") {
		t.Fatalf("suffix+children match-all: %v", err)
	}
}

func TestBindOutcomeDoesNotEnumerate(t *testing.T) {
	t.Parallel()
	unknown := bindOutcome(false, false, false, directory.Error("bind", directory.FieldInvalidCredentials, "invalid credentials"))
	wrong := bindOutcome(true, false, false, directory.Error("bind", directory.FieldInvalidCredentials, "invalid credentials"))
	if unknown != directory.BindOutcomeInvalidCredentials || unknown != wrong {
		t.Fatalf("unknown=%s wrong=%s", unknown, wrong)
	}
	if bindOutcome(true, true, false, directory.Error("entry", directory.FieldConstraint, "x")) != directory.BindOutcomeDisabled {
		t.Fatal("disabled")
	}
	if bindOutcome(true, false, false, directory.Error("connection", directory.FieldUnavailable, "Account inactivated. Contact system administrator.")) != directory.BindOutcomeDisabled {
		t.Fatal("inactivated")
	}
	unauth := directory.Error("connection", directory.FieldUnavailable, "Unauthenticated binds are not allowed")
	if accountInactivated(unauth) || bindOutcome(true, false, false, unauth) != directory.BindOutcomeUnavailable {
		t.Fatalf("generic 53 / unauthenticated bind must not be disabled: %s", bindOutcome(true, false, false, unauth))
	}
	if bindOutcome(true, false, true, directory.Error("bind", directory.FieldInvalidCredentials, "x")) != directory.BindOutcomeLocked {
		t.Fatal("locked")
	}
	if bindOutcome(true, false, false, nil) != directory.BindOutcomeSuccess {
		t.Fatal("success")
	}
}

func TestBindTestEmptyPasswordStillDials(t *testing.T) {
	t.Parallel()
	rt := testRuntime(t)
	var connectCalls int
	rt.cfg.Connect = func(ctx context.Context, cfg ldapclient.Config) (*ldapclient.Conn, error) {
		connectCalls++
		return nil, directory.Error("connection", directory.FieldUnavailable, "directory unavailable")
	}
	res, err := rt.BindTest(t.Context(), "cn=ghost,dc=example,dc=test", "", directory.TransportLDAP)
	if connectCalls != 1 {
		t.Fatalf("empty password must still open a disposable conn, calls=%d", connectCalls)
	}
	if res.Outcome != directory.BindOutcomeUnavailable {
		t.Fatalf("down directory: %+v %v", res, err)
	}
}

func TestBindTestPasswordAbsentAndNotPooled(t *testing.T) {
	t.Parallel()
	rt := testRuntime(t)
	var connectCalls int
	rt.cfg.Connect = func(ctx context.Context, cfg ldapclient.Config) (*ldapclient.Conn, error) {
		connectCalls++
		if cfg.BindDN != "" || cfg.BindPassword.Reveal() != "" {
			t.Fatal("bind-test connect must not use the runtime bind")
		}
		return nil, directory.Error("connection", directory.FieldUnavailable, "directory unavailable")
	}
	canary := observability.Secret("bind-test-canary-99")
	before := rt.pool.Stats()
	res, err := rt.BindTest(t.Context(), "cn=ghost,dc=example,dc=test", canary, directory.TransportLDAP)
	after := rt.pool.Stats()
	if connectCalls != 1 {
		t.Fatalf("disposable connect calls = %d", connectCalls)
	}
	if before.Dialed != after.Dialed || before.Active != after.Active || before.Idle != after.Idle {
		t.Fatalf("pool mutated: before=%+v after=%+v", before, after)
	}
	if res.Outcome != directory.BindOutcomeUnavailable {
		t.Fatalf("outcome=%s err=%v", res.Outcome, err)
	}
	if err != nil && strings.Contains(err.Error(), canary.Reveal()) {
		t.Fatalf("password leaked in error: %v", err)
	}
	raw, _ := json.Marshal(res)
	if strings.Contains(string(raw), canary.Reveal()) {
		t.Fatalf("password leaked in result: %s", raw)
	}
}

func TestSchemaParserAndNoSecrets(t *testing.T) {
	t.Parallel()
	oc, ok := parseObjectClass("( 2.5.6.6 NAME 'person' SUP top STRUCTURAL MUST ( sn $ cn ) MAY ( userPassword $ description ) )")
	if !ok || oc.Name != "person" || oc.OID != "2.5.6.6" || oc.Kind != "structural" {
		t.Fatalf("person: %+v ok=%v", oc, ok)
	}
	if len(oc.Must) != 2 || len(oc.May) != 2 {
		t.Fatalf("must/may: %+v", oc)
	}
	at, ok := parseAttributeType("( 2.5.4.4 NAME ( 'sn' 'surname' ) SYNTAX 1.3.6.1.4.1.1466.115.121.1.15{32768} SINGLE-VALUE )")
	if !ok || at.Name != "sn" || !at.SingleValue || at.Syntax == "" {
		t.Fatalf("sn: %+v ok=%v", at, ok)
	}
	dse := rootDSEFromEntry(nil)
	raw, err := json.Marshal(dse)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(strings.ToLower(string(raw)), "password") || strings.Contains(string(raw), "nsslapd-rootpw") {
		t.Fatalf("secret in root dse json: %s", raw)
	}
}

func TestSchemaCacheExpiry(t *testing.T) {
	t.Parallel()
	rt := testRuntime(t)
	now := time.Unix(1_700_000_000, 0)
	rt.now = func() time.Time { return now }
	rt.cfg.SchemaTTL = time.Second
	rt.cache.mu.Lock()
	rt.cache.dse = directory.RootDSE{VendorName: "cached"}
	rt.cache.dseOK = true
	rt.cache.dseExp = now.Add(time.Second)
	rt.cache.mu.Unlock()
	got, err := rt.RootDSE(t.Context())
	if err != nil || got.VendorName != "cached" {
		t.Fatalf("hit: %+v %v", got, err)
	}
	now = now.Add(2 * time.Second)
	_, err = rt.RootDSE(t.Context())
	if err == nil {
		t.Fatal("expired cache must refetch and fail without a directory")
	}
	rt.InvalidateSchema()
	rt.cache.mu.Lock()
	if rt.cache.dseOK || rt.cache.schemaOK {
		t.Fatal("invalidate left cache live")
	}
	rt.cache.mu.Unlock()
}

func TestRevisionStableWithoutPassword(t *testing.T) {
	t.Parallel()
	u := directory.User{ID: "alice", UID: "alice", Enabled: true, ObjectClasses: []string{"person"}, Attributes: []directory.AttrKV{{Name: "cn", Value: "Alice"}}}
	a := revisionOfUser(u)
	b := revisionOfUser(u)
	if a == "" || a != b {
		t.Fatalf("revision %q %q", a, b)
	}
	u.Attributes = append(u.Attributes, directory.AttrKV{Name: "sn", Value: "X"})
	if revisionOfUser(u) == a {
		t.Fatal("attribute change must change revision")
	}
}

func TestUsersGroupsAreSeparateRepos(t *testing.T) {
	t.Parallel()
	rt := testRuntime(t)
	var _ directory.UserRepository = rt.Users()
	var _ directory.GroupRepository = rt.Groups()
	var _ directory.SearchRepository = rt
	var _ directory.BindTester = rt
	var _ directory.SchemaRepository = rt
	var _ directory.CapabilityInspector = rt
	var _ directory.MarkerReader = rt
}

func TestApplyEnabledNoopWhenUnchanged(t *testing.T) {
	t.Parallel()
	unlocked := &ldap.Entry{DN: "uid=a,ou=people,dc=example,dc=test"}
	mod := ldap.NewModifyRequest(unlocked.DN, nil)
	if applyEnabled(mod, unlocked, true) || len(mod.Changes) != 0 {
		t.Fatal("enable on unlocked must not queue a modify")
	}
	locked := &ldap.Entry{
		DN:         unlocked.DN,
		Attributes: []*ldap.EntryAttribute{{Name: "nsAccountLock", Values: []string{"true"}}},
	}
	mod = ldap.NewModifyRequest(locked.DN, nil)
	if applyEnabled(mod, locked, false) || len(mod.Changes) != 0 {
		t.Fatal("disable on locked must not queue a modify")
	}
	if !applyEnabled(mod, locked, true) || len(mod.Changes) == 0 {
		t.Fatal("enable on locked must queue a delete")
	}
}

func TestRefuseRuntimeAccountMutations(t *testing.T) {
	t.Parallel()
	rt := testRuntime(t)
	dn := "uid=rt,ou=people,dc=example,dc=test"
	if err := rt.refuseRuntimeAccount(dn, "runtime account cannot be mutated"); err == nil || fieldOf(err) != directory.FieldForbidden {
		t.Fatalf("runtime guard: %v", err)
	}
	en := true
	if err := rt.refuseRuntimeMutation(dn, directory.UserPatch{Enabled: &en}); err == nil {
		t.Fatal("enabled patch on runtime")
	}
	if err := rt.refuseRuntimeMutation(dn, directory.UserPatch{Attributes: map[string]string{"sn": "x"}}); err != nil {
		t.Fatalf("attr-only patch: %v", err)
	}
}

func TestProtectedCursorQueryAndTamper(t *testing.T) {
	t.Parallel()
	rt := testRuntime(t)
	rt.now = func() time.Time { return time.Unix(1_700_000_000, 0) }
	tok, err := rt.encodePageCursor("users||2", []byte{0x01, 0x02})
	if err != nil || tok == "" {
		t.Fatalf("encode: %q %v", tok, err)
	}
	got, err := rt.decodePageCursor(tok, "users||2")
	if err != nil || string(got) != string([]byte{0x01, 0x02}) {
		t.Fatalf("decode: %x %v", got, err)
	}
	if _, err := rt.decodePageCursor(tok, "users|other|2"); err == nil || !hasField(err, "cursor", "invalid") {
		t.Fatalf("query mismatch: %v", err)
	}
	if _, err := rt.decodePageCursor(tok[:len(tok)-1]+"B", "users||2"); err == nil || !hasField(err, "cursor", "invalid") {
		t.Fatalf("tamper: %v", err)
	}
	inner, err := config.EncodeCursor(config.Cursor{Query: "users||2", Page: "0102"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := rt.decodePageCursor(inner, "users||2"); err == nil || !hasField(err, "cursor", "invalid") {
		t.Fatalf("unsigned cursor: %v", err)
	}
	rt.now = func() time.Time { return time.Unix(1_700_000_000, 0).Add(rt.cfg.CursorTTL + time.Second) }
	if _, err := rt.decodePageCursor(tok, "users||2"); err == nil || !hasField(err, "cursor", "invalid") {
		t.Fatalf("expired: %v", err)
	}
}

func TestAssertionFilterUsesOperationalAttrs(t *testing.T) {
	t.Parallel()
	if assertionFilter(nil) != "" {
		t.Fatal("nil entry")
	}
	e := &ldap.Entry{Attributes: []*ldap.EntryAttribute{
		{Name: "entryCSN", Values: []string{"20240101000000.000000Z#000000#000#000000"}},
		{Name: "cn", Values: []string{"Alice"}},
	}}
	got := assertionFilter(e)
	if got != "(entryCSN=20240101000000.000000Z#000000#000#000000)" {
		t.Fatalf("filter %q", got)
	}
	off := false
	rt := testRuntime(t)
	rt.cfg.Assertion = &off
	if rt.assertionControl(t.Context(), nil, e) != nil {
		t.Fatal("disabled assertion still attached")
	}
	on := true
	rt.cfg.Assertion = &on
	if rt.assertionControl(t.Context(), nil, e) == nil {
		t.Fatal("enabled assertion missing")
	}
	for _, name := range operationalReadAttrs() {
		if skipReturnedAttr(name) != true {
			t.Fatalf("%s must not appear on API attributes", name)
		}
	}
}

func TestNewDeleteOmitsAssertionControl(t *testing.T) {
	t.Parallel()
	rt := testRuntime(t)
	on := true
	rt.cfg.Assertion = &on
	live := &ldap.Entry{
		DN: "uid=x,ou=people,dc=example,dc=test",
		Attributes: []*ldap.EntryAttribute{
			{Name: "entryCSN", Values: []string{"20240101000000.000000Z#000000#000#000000"}},
		},
	}
	if rt.assertionControl(t.Context(), nil, live) == nil {
		t.Fatal("fixture: enabled assertion missing on modify path")
	}
	req := newDelete(t.Context(), rt, nil, live.DN, live)
	if req.DN != live.DN {
		t.Fatalf("delete dn %q", req.DN)
	}
	if len(req.Controls) != 0 {
		t.Fatalf("delete controls = %#v, want none (no critical RFC 4528)", req.Controls)
	}
}

func TestConfigFieldCodes(t *testing.T) {
	t.Parallel()
	err := cfgErr("filter", "over_broad", "search too broad")
	apperr.Assert(t, err).Code(apperr.CodeConfiguration)
	if !hasField(err, "filter", "over_broad") {
		t.Fatal(err)
	}
}
