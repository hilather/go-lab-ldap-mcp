//go:build integration

package dirsrv

import (
	"encoding/json"
	"errors"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/hilather/go-lab-ldap-mcp/internal/apperr"
	"github.com/hilather/go-lab-ldap-mcp/internal/directory"
	"github.com/hilather/go-lab-ldap-mcp/internal/directory/ds389"
	"github.com/hilather/go-lab-ldap-mcp/internal/directory/ldapclient"
	"github.com/hilather/go-lab-ldap-mcp/internal/observability"
)

const repoUserPass = "repo-user-pass-12"
const repoBindCanary = "repo-bind-canary-99"

type runtimeEnv struct {
	inst *Instance
	rt   *ds389.Runtime
	pool *ldapclient.Pool
}

func startRuntimeEnv(t *testing.T) *runtimeEnv {
	t.Helper()
	inst := Start(t)
	_, guest := stageApply(t, inst, "dc=example,dc=test")
	if out, err := execApply(t, inst, guest, nil); err != nil {
		t.Fatalf("apply: %v\n%s", err, out)
	}
	ca := filepath.Join(t.TempDir(), "ca.crt")
	inst.WriteCA(t, ca)
	cfg := ldapclient.Config{
		Address:      inst.LDAPSAddr,
		Transport:    directory.TransportLDAPS,
		CAFile:       ca,
		ServerName:   inst.Hostname(t),
		BindDN:       "uid=rt,ou=people,dc=example,dc=test",
		BindPassword: observability.Secret("runtime-secret"),
		DialTimeout:  8 * time.Second,
		PoolSize:     4,
	}
	pool, err := ldapclient.NewPool(cfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = pool.Close() })
	if err := pool.Do(t.Context(), func(c *ldapclient.Conn) error { return c.Ping(t.Context()) }); err != nil {
		t.Fatalf("runtime pool bind: %v", err)
	}
	rt, err := ds389.NewRuntime(pool, ds389.RuntimeConfig{
		Suffix:    "dc=example,dc=test",
		PeopleDN:  "ou=people,dc=example,dc=test",
		GroupsDN:  "ou=groups,dc=example,dc=test",
		RuntimeDN: "uid=rt,ou=people,dc=example,dc=test",
		Client:    cfg,
		SchemaTTL: time.Minute,
	})
	if err != nil {
		t.Fatal(err)
	}
	return &runtimeEnv{inst: inst, rt: rt, pool: pool}
}

func TestRuntimeRepositories(t *testing.T) {
	env := startRuntimeEnv(t)
	t.Run("users", func(t *testing.T) { testRuntimeUsers(t, env) })
	t.Run("groups", func(t *testing.T) { testRuntimeGroups(t, env) })
	t.Run("search", func(t *testing.T) { testRuntimeSearch(t, env) })
	t.Run("bindtest", func(t *testing.T) { testRuntimeBindTest(t, env) })
	t.Run("schema", func(t *testing.T) { testRuntimeSchema(t, env) })
	t.Run("revisions", func(t *testing.T) { testRuntimeRevisionsAndCursors(t, env) })
	t.Run("assertion", func(t *testing.T) { testRuntimeAssertionControl(t, env) })
}

func testRuntimeUsers(t *testing.T, env *runtimeEnv) {
	users := env.rt.Users()
	alice, err := users.Add(t.Context(), directory.UserSpec{
		ID:       "alice",
		Password: observability.Secret(repoUserPass),
		Attributes: map[string]string{
			"sn":          "Seed",
			"givenName":   "Alice",
			"description": "operator",
		},
	})
	if err != nil {
		t.Fatalf("add: %v", err)
	}
	if alice.ID != "alice" || alice.UID != "alice" || !alice.Enabled || alice.Revision == "" {
		t.Fatalf("add read-back: %+v", alice)
	}
	assertNoPassword(t, alice, repoUserPass)

	got, err := users.Get(t.Context(), "alice")
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	if got.Revision != alice.Revision {
		t.Fatalf("revision changed on read %q vs %q", got.Revision, alice.Revision)
	}
	assertNoPassword(t, got, repoUserPass)

	_, err = users.Add(t.Context(), directory.UserSpec{
		ID: "carol", Password: observability.Secret(repoUserPass),
		Attributes: map[string]string{"userPassword": "nope", "sn": "X"},
	})
	if err == nil {
		t.Fatal("forbidden userPassword attribute must fail")
	}
	assertField(t, err, "attributes.userPassword", "forbidden_attribute")

	_, err = users.Modify(t.Context(), "alice", directory.UserPatch{Attributes: map[string]string{"nsAccountLock": "true"}})
	if err == nil {
		t.Fatal("forbidden nsAccountLock via attributes must fail")
	}
	assertField(t, err, "attributes.nsAccountLock", "forbidden_attribute")

	_, err = users.Modify(t.Context(), "alice", directory.UserPatch{Attributes: map[string]string{"sn": ""}})
	if err == nil {
		t.Fatal("empty sn must fail")
	}

	en := true
	noop, err := users.Modify(t.Context(), "alice", directory.UserPatch{Enabled: &en})
	if err != nil {
		t.Fatalf("modify enabled no-op: %v", err)
	}
	if !noop.Enabled {
		t.Fatal("no-op enable cleared enabled")
	}

	patched, err := users.Modify(t.Context(), "alice", directory.UserPatch{Attributes: map[string]string{"description": "updated"}})
	if err != nil {
		t.Fatalf("modify: %v", err)
	}
	if attrValue(patched, "description") != "updated" {
		t.Fatalf("modify read-back: %+v", patched.Attributes)
	}

	disabled, err := users.SetEnabled(t.Context(), "alice", false, patched.Revision)
	if err != nil {
		t.Fatalf("disable: %v", err)
	}
	if disabled.Enabled {
		t.Fatal("expected disabled")
	}
	if err := userBind(t, env.inst, disabled.DN, repoUserPass); err == nil {
		t.Fatal("disabled user must not bind")
	}
	enabled, err := users.SetEnabled(t.Context(), "alice", true, disabled.Revision)
	if err != nil {
		t.Fatalf("enable: %v", err)
	}
	if !enabled.Enabled {
		t.Fatal("expected enabled")
	}
	if err := userBind(t, env.inst, enabled.DN, repoUserPass); err != nil {
		t.Fatalf("enabled bind: %v", err)
	}

	nextPW := "repo-user-pass-99"
	if err := users.SetPassword(t.Context(), "alice", observability.Secret(nextPW), enabled.Revision); err != nil {
		t.Fatalf("set password: %v", err)
	}
	if err := userBind(t, env.inst, enabled.DN, nextPW); err != nil {
		t.Fatalf("bind after password: %v", err)
	}
	afterPW, err := users.Get(t.Context(), "alice")
	if err != nil {
		t.Fatal(err)
	}
	assertNoPassword(t, afterPW, nextPW)

	page, err := users.List(t.Context(), directory.UserListQuery{PageSize: 50, Q: "ali"})
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if !hasUser(page.Items, "alice") {
		t.Fatalf("list missing alice: %+v", page.Items)
	}

	if _, err := users.SetEnabled(t.Context(), "rt", false, ""); err == nil || fieldCode(err) != directory.FieldForbidden {
		t.Fatalf("disable runtime: %v", err)
	}
	if err := users.SetPassword(t.Context(), "rt", observability.Secret("repo-runtime-pass-12"), ""); err == nil || fieldCode(err) != directory.FieldForbidden {
		t.Fatalf("rotate runtime: %v", err)
	}

	if err := users.Delete(t.Context(), "alice", afterPW.Revision); err != nil {
		t.Fatalf("delete: %v", err)
	}
	if _, err := users.Get(t.Context(), "alice"); err == nil {
		t.Fatal("get after delete")
	}
}

func testRuntimeGroups(t *testing.T, env *runtimeEnv) {
	users := env.rt.Users()
	groups := env.rt.Groups()
	alice, err := users.Add(t.Context(), directory.UserSpec{ID: "g-alice", Password: observability.Secret(repoUserPass), Attributes: map[string]string{"sn": "A"}})
	if err != nil {
		t.Fatalf("alice: %v", err)
	}
	_, err = users.Add(t.Context(), directory.UserSpec{ID: "g-bob", Password: observability.Secret(repoUserPass), Attributes: map[string]string{"sn": "B"}})
	if err != nil {
		t.Fatalf("bob: %v", err)
	}
	_, err = groups.Add(t.Context(), directory.GroupSpec{ID: "empty"})
	if err == nil {
		t.Fatal("empty group must be rejected")
	}
	assertField(t, err, "members", "empty_group")

	staff, err := groups.Add(t.Context(), directory.GroupSpec{
		ID:      "staff",
		Members: []directory.MemberRef{{Kind: "user", ID: "g-alice"}},
	})
	if err != nil {
		t.Fatalf("add staff: %v", err)
	}
	if len(staff.Members) != 1 {
		t.Fatalf("staff members: %+v", staff.Members)
	}

	sum, err := groups.AddMembers(t.Context(), "staff", []directory.MemberRef{{Kind: "user", ID: "g-alice"}}, staff.Revision)
	if err != nil {
		t.Fatalf("idempotent add: %v", err)
	}
	if len(sum.Added) != 0 || len(sum.Unchanged) != 1 {
		t.Fatalf("idempotent add summary: %+v", sum)
	}

	sum, err = groups.AddMembers(t.Context(), "staff", []directory.MemberRef{{Kind: "user", ID: "g-bob"}}, sum.Revision)
	if err != nil {
		t.Fatalf("add bob: %v", err)
	}
	if len(sum.Added) != 1 || sum.Added[0].ID != "g-bob" {
		t.Fatalf("add bob summary: %+v", sum)
	}
	gotAlice, err := users.Get(t.Context(), "g-alice")
	if err != nil {
		t.Fatal(err)
	}
	if !hasGroup(gotAlice.Groups, "staff") {
		t.Fatalf("alice memberOf missing staff: %+v", gotAlice.Groups)
	}
	gotBob, err := users.Get(t.Context(), "g-bob")
	if err != nil {
		t.Fatal(err)
	}
	if !hasGroup(gotBob.Groups, "staff") {
		t.Fatalf("bob memberOf missing staff: %+v", gotBob.Groups)
	}

	sum, err = groups.RemoveMembers(t.Context(), "staff", []directory.MemberRef{{Kind: "user", ID: "g-bob"}}, sum.Revision)
	if err != nil {
		t.Fatalf("remove bob: %v", err)
	}
	if len(sum.Removed) != 1 {
		t.Fatalf("remove summary: %+v", sum)
	}
	sum, err = groups.RemoveMembers(t.Context(), "staff", []directory.MemberRef{{Kind: "user", ID: "g-bob"}}, sum.Revision)
	if err != nil {
		t.Fatalf("idempotent remove: %v", err)
	}
	if len(sum.Removed) != 0 || len(sum.Unchanged) != 1 {
		t.Fatalf("idempotent remove: %+v", sum)
	}
	gotBob, err = users.Get(t.Context(), "g-bob")
	if err != nil {
		t.Fatal(err)
	}
	if hasGroup(gotBob.Groups, "staff") {
		t.Fatalf("bob still memberOf staff: %+v", gotBob.Groups)
	}

	_, err = groups.ReplaceMembers(t.Context(), "staff", nil, sum.Revision)
	if err == nil {
		t.Fatal("replace empty must fail")
	}
	assertField(t, err, "members", "empty_group")

	_, err = groups.RemoveMembers(t.Context(), "staff", []directory.MemberRef{{Kind: "user", ID: "g-alice"}}, sum.Revision)
	if err == nil {
		t.Fatal("remove last member must fail")
	}
	assertField(t, err, "members", "empty_group")

	if err := users.Delete(t.Context(), "g-bob", gotBob.Revision); err != nil {
		t.Fatalf("delete bob: %v", err)
	}
	staffGot, err := groups.Get(t.Context(), "staff")
	if err != nil {
		t.Fatal(err)
	}
	for _, m := range staffGot.Members {
		if m.ID == "g-bob" || strings.Contains(m.DN, "g-bob") {
			t.Fatalf("RI left bob in staff: %+v", staffGot.Members)
		}
	}

	if err := groups.Delete(t.Context(), "staff", staffGot.Revision); err != nil {
		t.Fatalf("delete staff: %v", err)
	}
	gotAlice, err = users.Get(t.Context(), "g-alice")
	if err != nil {
		t.Fatal(err)
	}
	if hasGroup(gotAlice.Groups, "staff") {
		t.Fatalf("alice memberOf leftover after group delete: %+v", gotAlice.Groups)
	}
	_ = users.Delete(t.Context(), "g-alice", alice.Revision)
}

func testRuntimeSearch(t *testing.T, env *runtimeEnv) {
	users := env.rt.Users()
	for _, id := range []string{"s-a", "s-b", "s-c"} {
		if _, err := users.Add(t.Context(), directory.UserSpec{ID: id, Password: observability.Secret(repoUserPass), Attributes: map[string]string{"sn": "S"}}); err != nil {
			t.Fatalf("seed %s: %v", id, err)
		}
	}
	_, err := env.rt.Search(t.Context(), directory.SearchQuery{Filter: ""})
	if err == nil {
		t.Fatal("empty filter")
	}
	assertField(t, err, "filter", "empty")

	_, err = env.rt.Search(t.Context(), directory.SearchQuery{Base: "dc=example,dc=test", Scope: directory.SearchScopeSub, Filter: "(objectClass=*)"})
	if err == nil {
		t.Fatal("over-broad")
	}
	assertField(t, err, "filter", "over_broad")
	_, err = env.rt.Search(t.Context(), directory.SearchQuery{Base: "dc=example,dc=test", Scope: directory.SearchScopeSub, Filter: "(&(objectClass=*))"})
	if err == nil {
		t.Fatal("over-broad &")
	}
	assertField(t, err, "filter", "over_broad")
	_, err = env.rt.Search(t.Context(), directory.SearchQuery{Base: "dc=example,dc=test", Scope: directory.SearchScopeChildren, Filter: "(objectClass=*)"})
	if err == nil {
		t.Fatal("over-broad children")
	}
	assertField(t, err, "filter", "over_broad")

	_, err = env.rt.Search(t.Context(), directory.SearchQuery{Base: "cn=config", Filter: "(objectClass=*)"})
	if err == nil {
		t.Fatal("escaped to cn=config")
	}
	if fieldCode(err) != directory.FieldForbidden {
		t.Fatalf("escape: %v", err)
	}
	_, err = env.rt.Search(t.Context(), directory.SearchQuery{Base: "dc=other,dc=com", Filter: "(uid=s-a)"})
	if err == nil || fieldCode(err) != directory.FieldForbidden {
		t.Fatalf("other suffix: %v", err)
	}

	_, err = env.rt.Search(t.Context(), directory.SearchQuery{Filter: "(uid=s-a"})
	if err == nil {
		t.Fatal("malformed")
	}
	assertField(t, err, "filter", "unbalanced")
	_, err = env.rt.Search(t.Context(), directory.SearchQuery{Filter: strings.Repeat("(", 20) + strings.Repeat(")", 20)})
	if err == nil {
		t.Fatal("too deep")
	}
	assertField(t, err, "filter", "too_deep")
	_, err = env.rt.Search(t.Context(), directory.SearchQuery{Filter: "(uid=" + strings.Repeat("a", 5000) + ")"})
	if err == nil {
		t.Fatal("too long")
	}
	assertField(t, err, "filter", "too_long")

	page, err := env.rt.Search(t.Context(), directory.SearchQuery{
		Base: "ou=people,dc=example,dc=test", Scope: directory.SearchScopeOne,
		Filter: "(uid=s-a)", Attributes: []string{"uid", "userPassword"},
	})
	if err != nil {
		t.Fatalf("people search: %v", err)
	}
	if len(page.Entries) != 1 {
		t.Fatalf("entries: %+v", page.Entries)
	}
	for _, a := range page.Entries[0].Attributes {
		if strings.EqualFold(a.Name, "userPassword") || a.Value == repoUserPass {
			t.Fatalf("password leaked in search: %+v", page.Entries[0])
		}
	}

	one, err := env.rt.Search(t.Context(), directory.SearchQuery{
		Base: "dc=example,dc=test", Scope: directory.SearchScopeOne, Filter: "(objectClass=*)",
	})
	if err != nil {
		t.Fatalf("suffix+one match-all: %v", err)
	}
	if len(one.Entries) == 0 {
		t.Fatal("expected people/groups containers")
	}

	limited, err := ds389.NewRuntime(env.pool, ds389.RuntimeConfig{
		Suffix:          "dc=example,dc=test",
		PeopleDN:        "ou=people,dc=example,dc=test",
		GroupsDN:        "ou=groups,dc=example,dc=test",
		SearchSizeLimit: 2,
		SearchTimeLimit: time.Second,
		PageSizeDefault: 2,
		PageSizeMax:     2,
	})
	if err != nil {
		t.Fatal(err)
	}
	got, err := limited.Search(t.Context(), directory.SearchQuery{
		Base: "ou=people,dc=example,dc=test", Scope: directory.SearchScopeOne,
		Filter: "(objectClass=inetOrgPerson)", PageSize: 2,
	})
	if err != nil && fieldCode(err) != directory.FieldConstraint {
		t.Fatalf("size-limited search: %v", err)
	}
	if err == nil && len(got.Entries) > 2 {
		t.Fatalf("size limit not applied: %d entries", len(got.Entries))
	}
}

func testRuntimeBindTest(t *testing.T, env *runtimeEnv) {
	users := env.rt.Users()
	u, err := users.Add(t.Context(), directory.UserSpec{ID: "bindme", Password: observability.Secret(repoUserPass), Attributes: map[string]string{"sn": "B"}})
	if err != nil {
		t.Fatalf("add: %v", err)
	}
	before := env.pool.Stats()
	ok, err := env.rt.BindTest(t.Context(), "bindme", observability.Secret(repoUserPass), directory.TransportLDAPS)
	if err != nil || ok.Outcome != directory.BindOutcomeSuccess {
		t.Fatalf("success: %+v %v", ok, err)
	}
	wrong, err := env.rt.BindTest(t.Context(), "bindme", observability.Secret(repoBindCanary), directory.TransportLDAPS)
	if err != nil {
		t.Fatalf("wrong: %v", err)
	}
	unknown, err := env.rt.BindTest(t.Context(), "no-such-user", observability.Secret(repoBindCanary), directory.TransportLDAPS)
	if err != nil {
		t.Fatalf("unknown: %v", err)
	}
	if wrong.Outcome != directory.BindOutcomeInvalidCredentials || unknown.Outcome != wrong.Outcome {
		t.Fatalf("enumeration: wrong=%s unknown=%s", wrong.Outcome, unknown.Outcome)
	}
	emptyLive, err := env.rt.BindTest(t.Context(), "bindme", "", directory.TransportLDAPS)
	if err != nil {
		t.Fatalf("empty live: %v", err)
	}
	emptyUnknown, err := env.rt.BindTest(t.Context(), "no-such-user", "", directory.TransportLDAPS)
	if err != nil {
		t.Fatalf("empty unknown: %v", err)
	}
	if emptyLive.Outcome != directory.BindOutcomeInvalidCredentials || emptyUnknown.Outcome != emptyLive.Outcome {
		t.Fatalf("empty password: live=%s unknown=%s", emptyLive.Outcome, emptyUnknown.Outcome)
	}
	after := env.pool.Stats()
	if after.Active != before.Active {
		t.Fatalf("bind-test left pool active: before=%+v after=%+v", before, after)
	}
	if err := env.pool.Do(t.Context(), func(c *ldapclient.Conn) error { return c.Ping(t.Context()) }); err != nil {
		t.Fatalf("pool poisoned after bind-test: %v", err)
	}
	for _, res := range []directory.BindTestResult{ok, wrong, unknown} {
		raw, _ := json.Marshal(res)
		if strings.Contains(string(raw), repoBindCanary) || strings.Contains(string(raw), repoUserPass) {
			t.Fatalf("password in result: %s", raw)
		}
	}

	disabled, err := users.SetEnabled(t.Context(), "bindme", false, u.Revision)
	if err != nil {
		t.Fatalf("disable: %v", err)
	}
	locked, err := env.rt.BindTest(t.Context(), "bindme", observability.Secret(repoUserPass), directory.TransportLDAPS)
	if err != nil {
		t.Fatalf("disabled bind-test: %v", err)
	}
	if locked.Outcome != directory.BindOutcomeDisabled && locked.Outcome != directory.BindOutcomeInvalidCredentials {
		t.Fatalf("disabled outcome=%s", locked.Outcome)
	}
	_, _ = users.SetEnabled(t.Context(), "bindme", true, disabled.Revision)
}

func testRuntimeSchema(t *testing.T, env *runtimeEnv) {
	dse, err := env.rt.RootDSE(t.Context())
	if err != nil {
		t.Fatalf("root dse: %v", err)
	}
	if dse.VendorName == "" && dse.VendorVersion == "" {
		t.Fatalf("empty vendor: %+v", dse)
	}
	foundSuffix := false
	for _, nc := range dse.NamingContexts {
		if strings.Contains(strings.ToLower(nc), "dc=example") {
			foundSuffix = true
		}
	}
	if !foundSuffix {
		t.Fatalf("namingContexts: %+v", dse.NamingContexts)
	}
	raw, _ := json.Marshal(dse)
	low := strings.ToLower(string(raw))
	if strings.Contains(low, "nsslapd-rootpw") || strings.Contains(low, "\"userpassword\":") {
		t.Fatalf("secret in root dse: %s", raw)
	}

	sch, err := env.rt.Schema(t.Context())
	if err != nil {
		t.Fatalf("schema: %v", err)
	}
	if !hasOC(sch, "person") || !hasOC(sch, "inetOrgPerson") || !hasAT(sch, "cn") || !hasAT(sch, "sn") {
		t.Fatalf("schema missing expected types: oc=%d at=%d", len(sch.ObjectClasses), len(sch.Attributes))
	}
	sraw, _ := json.Marshal(sch)
	if strings.Contains(strings.ToLower(string(sraw)), "nsslapd-rootpw") {
		t.Fatalf("config secret in schema: %s", sraw)
	}
	again, err := env.rt.Schema(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	if len(again.ObjectClasses) != len(sch.ObjectClasses) || len(again.Attributes) != len(sch.Attributes) {
		t.Fatal("cached schema changed")
	}

	env.rt.InvalidateSchema()
	refetch, err := env.rt.Schema(t.Context())
	if err != nil {
		t.Fatalf("refetch after invalidate: %v", err)
	}
	if !hasOC(refetch, "person") {
		t.Fatal("reconnect/invalidate refetch missing person")
	}

	caps, err := env.rt.Capabilities(t.Context())
	if err != nil {
		t.Fatalf("capabilities: %v", err)
	}
	if caps.EngineVendor != dse.VendorName || !caps.RequiredOK {
		t.Fatalf("capabilities not consumed from root dse: %+v dse=%+v", caps, dse)
	}
	if len(caps.Controls) == 0 && len(dse.SupportedControls) > 0 {
		t.Fatal("capabilities dropped controls")
	}
}

func assertNoPassword(t *testing.T, u directory.User, secrets ...string) {
	t.Helper()
	raw, err := json.Marshal(u)
	if err != nil {
		t.Fatal(err)
	}
	s := string(raw)
	if strings.Contains(strings.ToLower(s), "userpassword") {
		t.Fatalf("userPassword in json: %s", s)
	}
	for _, sec := range secrets {
		if sec != "" && strings.Contains(s, sec) {
			t.Fatalf("secret %q in user json: %s", sec, s)
		}
	}
	for _, a := range u.Attributes {
		if strings.EqualFold(a.Name, "userPassword") {
			t.Fatal("userPassword attribute returned")
		}
		for _, sec := range secrets {
			if a.Value == sec {
				t.Fatal("password value returned")
			}
		}
	}
}

func assertField(t *testing.T, err error, path, code string) {
	t.Helper()
	var e *apperr.Error
	if !errors.As(err, &e) {
		t.Fatalf("not apperr: %v", err)
	}
	for _, f := range e.Fields() {
		if (path == "" || f.Path == path) && f.Code == code {
			return
		}
	}
	t.Fatalf("missing %s/%s in %#v", path, code, e.Fields())
}

func fieldCode(err error) string {
	var e *apperr.Error
	if !errors.As(err, &e) {
		return ""
	}
	for _, f := range e.Fields() {
		if f.Code != "" {
			return f.Code
		}
	}
	return ""
}

func attrValue(u directory.User, name string) string {
	for _, a := range u.Attributes {
		if strings.EqualFold(a.Name, name) {
			return a.Value
		}
	}
	return ""
}

func hasUser(users []directory.User, id string) bool {
	for _, u := range users {
		if u.ID == id {
			return true
		}
	}
	return false
}

func hasGroup(groups []directory.GroupID, id string) bool {
	for _, g := range groups {
		if string(g) == id {
			return true
		}
	}
	return false
}

func hasOC(s directory.Schema, name string) bool {
	for _, oc := range s.ObjectClasses {
		if strings.EqualFold(oc.Name, name) {
			return true
		}
	}
	return false
}

func testRuntimeRevisionsAndCursors(t *testing.T, env *runtimeEnv) {
	users := env.rt.Users()
	u, err := users.Add(t.Context(), directory.UserSpec{
		ID: "rev-a", Password: observability.Secret(repoUserPass),
		Attributes: map[string]string{"sn": "Rev", "description": "one"},
	})
	if err != nil {
		t.Fatalf("add: %v", err)
	}
	again, err := users.Get(t.Context(), "rev-a")
	if err != nil {
		t.Fatal(err)
	}
	if again.Revision != u.Revision || again.Revision == "" {
		t.Fatalf("unchanged read revision %q vs %q", again.Revision, u.Revision)
	}
	for _, a := range again.Attributes {
		switch strings.ToLower(a.Name) {
		case "entrycsn", "modifytimestamp", "entryuuid", "userpassword":
			t.Fatalf("operational/secret attr leaked: %+v", a)
		}
	}
	patched, err := users.Modify(t.Context(), "rev-a", directory.UserPatch{Attributes: map[string]string{"description": "two"}})
	if err != nil {
		t.Fatalf("modify: %v", err)
	}
	if patched.Revision == "" || patched.Revision == u.Revision {
		t.Fatalf("attribute change must alter revision: before=%q after=%q", u.Revision, patched.Revision)
	}

	for i := 0; i < 3; i++ {
		id := "cur-" + string(rune('a'+i))
		if _, err := users.Add(t.Context(), directory.UserSpec{
			ID: id, Password: observability.Secret(repoUserPass),
			Attributes: map[string]string{"sn": "C"},
		}); err != nil {
			t.Fatalf("seed %s: %v", id, err)
		}
	}
	page, err := users.List(t.Context(), directory.UserListQuery{PageSize: 1, Q: "cur-"})
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if page.NextCursor == "" {
		t.Fatal("expected protected next cursor")
	}
	if _, err := users.List(t.Context(), directory.UserListQuery{PageSize: 1, Q: "other", Cursor: page.NextCursor}); err == nil {
		t.Fatal("cursor reused with a different query")
	} else {
		assertField(t, err, "cursor", "invalid")
	}
	tampered := page.NextCursor[:len(page.NextCursor)-1] + "A"
	if _, err := users.List(t.Context(), directory.UserListQuery{PageSize: 1, Q: "cur-", Cursor: tampered}); err == nil {
		t.Fatal("tampered cursor accepted")
	} else {
		assertField(t, err, "cursor", "invalid")
	}
	next, err := users.List(t.Context(), directory.UserListQuery{PageSize: 1, Q: "cur-", Cursor: page.NextCursor})
	if err != nil {
		t.Fatalf("valid cursor: %v", err)
	}
	if len(next.Items) == 0 {
		t.Fatal("expected next page")
	}
}

func testRuntimeAssertionControl(t *testing.T, env *runtimeEnv) {
	caps, err := env.rt.Capabilities(t.Context())
	if err != nil {
		t.Fatalf("capabilities: %v", err)
	}
	users := env.rt.Users()
	u, err := users.Add(t.Context(), directory.UserSpec{
		ID: "assert-a", Password: observability.Secret(repoUserPass),
		Attributes: map[string]string{"sn": "Assert"},
	})
	if err != nil {
		t.Fatalf("add: %v", err)
	}
	runtimeReplace(t, env.inst, u.DN, "userPassword", repoUserPass+"x")
	afterPW, err := users.Get(t.Context(), "assert-a")
	if err != nil {
		t.Fatal(err)
	}
	if afterPW.Revision != u.Revision {
		t.Fatalf("password is not API-exposed; revision changed %q -> %q", u.Revision, afterPW.Revision)
	}
	_, err = users.SetEnabled(t.Context(), "assert-a", false, afterPW.Revision)
	if !caps.HasAssertionControl() {
		t.Logf("assertion control %s absent from Controls=%v; residual TOCTOU race documented (KD-R24)", directory.ControlAssertionOID, caps.Controls)
		if err != nil {
			t.Fatalf("without assertion, revision-matched SetEnabled should proceed: %v", err)
		}
		return
	}
	if err == nil {
		t.Fatal("assertion control advertised but concurrent password write was not detected")
	}
	if fieldCode(err) != directory.FieldConflict {
		t.Fatalf("assertion fail: %v", err)
	}
}

func runtimeReplace(t *testing.T, inst *Instance, dn, attr, value string) {
	t.Helper()
	ldif := "dn: " + dn + "\nchangetype: modify\nreplace: " + attr + "\n" + attr + ": " + value + "\n"
	cmd := exec.Command("docker", "exec", "-i", inst.Name,
		"ldapmodify", "-x", "-H", "ldaps://127.0.0.1:3636", "-o", "tls_reqcert=never",
		"-D", "uid=rt,ou=people,dc=example,dc=test", "-w", "runtime-secret")
	cmd.Stdin = strings.NewReader(ldif)
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("direct ldap replace %s: %v\n%s", attr, err, redactLogs(string(out), value, "runtime-secret"))
	}
}

func hasAT(s directory.Schema, name string) bool {
	for _, at := range s.Attributes {
		if strings.EqualFold(at.Name, name) {
			return true
		}
	}
	return false
}
