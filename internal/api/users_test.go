package api

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/hilather/go-lab-ldap-mcp/api/generated"
	"github.com/hilather/go-lab-ldap-mcp/internal/app"
	"github.com/hilather/go-lab-ldap-mcp/internal/auth"
	"github.com/hilather/go-lab-ldap-mcp/internal/directory"
	"github.com/hilather/go-lab-ldap-mcp/internal/observability"
)

const (
	readOnlyToken     = "lab-test-read-only-token-value-32"
	passwordOnlyToken = "lab-test-password-only-token-32x"
	userPass          = "lab-handler-user-pass-12"
)

func directoryServer(t *testing.T) (*Server, *memUsers, *memGroups) {
	t.Helper()
	users := newMemUsers()
	groups := newMemGroups()
	svc := app.New(app.Deps{
		Users:    users,
		Groups:   groups,
		PeopleDN: "ou=people,dc=example,dc=test",
		GroupsDN: "ou=groups,dc=example,dc=test",
	})
	reg, err := auth.NewRegistry([]auth.Token{
		{ID: "admin", Scopes: []string{auth.ScopeDirectoryRead, auth.ScopeDirectoryWrite, auth.ScopeDirectoryPassword}, Secret: observability.Secret(testToken)},
		{ID: "writer", Scopes: []string{auth.ScopeDirectoryWrite}, Secret: observability.Secret(writeOnlyToken)},
		{ID: "reader", Scopes: []string{auth.ScopeDirectoryRead}, Secret: observability.Secret(readOnlyToken)},
		{ID: "pw", Scopes: []string{auth.ScopeDirectoryPassword}, Secret: observability.Secret(passwordOnlyToken)},
		{ID: "auditor", Scopes: []string{auth.ScopeAuditRead}, Secret: observability.Secret(auditOnlyToken)},
	})
	if err != nil {
		t.Fatal(err)
	}
	s, err := New(Options{
		Registry: reg,
		Sessions: auth.NewStore(auth.DefaultSessionConfig()),
		Users:    svc.Users,
		Groups:   svc.Groups,
		System:   testQuery(),
	})
	if err != nil {
		t.Fatal(err)
	}
	return s, users, groups
}

func TestUserCRUDAndRevision(t *testing.T) {
	t.Parallel()
	s, _, _ := directoryServer(t)
	h := s.Handler()

	create := httptest.NewRequest(http.MethodPost, "/api/v1/users", strings.NewReader(`{"id":"alice","password":"`+userPass+`","attributes":{"sn":"Example"}}`))
	create.Header.Set("Authorization", "Bearer "+testToken)
	create.Header.Set("Content-Type", "application/json")
	cr := httptest.NewRecorder()
	h.ServeHTTP(cr, create)
	if cr.Code != http.StatusCreated {
		t.Fatalf("create %d %s", cr.Code, cr.Body.String())
	}
	if loc := cr.Header().Get("Location"); loc != "/api/v1/users/alice" {
		t.Fatalf("location %q", loc)
	}
	etag := cr.Header().Get("ETag")
	if etag == "" || etag[0] != '"' {
		t.Fatalf("etag %q", etag)
	}
	if cr.Header().Get("Cache-Control") != "no-store" {
		t.Fatal("create cache")
	}
	assertNoSecret(t, cr.Body.String(), userPass)
	var created generated.User
	decodeOpenAPI(t, cr, &created)
	if created.Id != "alice" || created.Uid != "alice" || created.Revision == "" {
		t.Fatalf("created %+v", created)
	}
	var raw map[string]any
	if err := json.Unmarshal(cr.Body.Bytes(), &raw); err != nil {
		t.Fatal(err)
	}
	if _, ok := raw["password"]; ok {
		t.Fatalf("password field in user response: %s", cr.Body.String())
	}
	if created.Attributes == nil || created.ObjectClasses == nil {
		t.Fatalf("nil slices %+v", created)
	}

	get := httptest.NewRequest(http.MethodGet, "/api/v1/users/alice", nil)
	get.Header.Set("Authorization", "Bearer "+testToken)
	gr := httptest.NewRecorder()
	h.ServeHTTP(gr, get)
	if gr.Code != http.StatusOK {
		t.Fatalf("get %d %s", gr.Code, gr.Body.String())
	}
	if gr.Header().Get("ETag") != etag {
		t.Fatalf("get etag %q want %q", gr.Header().Get("ETag"), etag)
	}
	assertNoSecret(t, gr.Body.String(), userPass)

	missing := httptest.NewRequest(http.MethodPatch, "/api/v1/users/alice", strings.NewReader(`{"attributes":{"description":"x"}}`))
	missing.Header.Set("Authorization", "Bearer "+testToken)
	missing.Header.Set("Content-Type", "application/json")
	mr := httptest.NewRecorder()
	h.ServeHTTP(mr, missing)
	if mr.Code != http.StatusPreconditionFailed {
		t.Fatalf("missing if-match %d %s", mr.Code, mr.Body.String())
	}
	assertProblem(t, mr, "configuration")

	stale := httptest.NewRequest(http.MethodPatch, "/api/v1/users/alice", strings.NewReader(`{"attributes":{"description":"x"}}`))
	stale.Header.Set("Authorization", "Bearer "+testToken)
	stale.Header.Set("Content-Type", "application/json")
	stale.Header.Set("If-Match", `"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"`)
	sr := httptest.NewRecorder()
	h.ServeHTTP(sr, stale)
	if sr.Code != http.StatusPreconditionFailed {
		t.Fatalf("stale %d %s", sr.Code, sr.Body.String())
	}
	assertProblem(t, sr, "directory")

	patch := httptest.NewRequest(http.MethodPatch, "/api/v1/users/alice", strings.NewReader(`{"attributes":{"description":"x"}}`))
	patch.Header.Set("Authorization", "Bearer "+testToken)
	patch.Header.Set("Content-Type", "application/json")
	patch.Header.Set("If-Match", etag)
	pr := httptest.NewRecorder()
	h.ServeHTTP(pr, patch)
	if pr.Code != http.StatusOK {
		t.Fatalf("patch %d %s", pr.Code, pr.Body.String())
	}
	assertNoSecret(t, pr.Body.String(), userPass)
	var updated generated.User
	decodeOpenAPI(t, pr, &updated)
	if updated.Revision == created.Revision {
		t.Fatal("patch must change revision")
	}
	next := pr.Header().Get("ETag")

	list := httptest.NewRequest(http.MethodGet, "/api/v1/users?q=ali", nil)
	list.Header.Set("Authorization", "Bearer "+testToken)
	lr := httptest.NewRecorder()
	h.ServeHTTP(lr, list)
	if lr.Code != http.StatusOK {
		t.Fatalf("list %d %s", lr.Code, lr.Body.String())
	}
	assertNoSecret(t, lr.Body.String(), userPass)
	var page generated.UserPage
	decodeOpenAPI(t, lr, &page)
	if len(page.Items) != 1 || page.Items[0].Id != "alice" {
		t.Fatalf("list %+v", page)
	}

	delMissing := httptest.NewRequest(http.MethodDelete, "/api/v1/users/alice", nil)
	delMissing.Header.Set("Authorization", "Bearer "+testToken)
	dr0 := httptest.NewRecorder()
	h.ServeHTTP(dr0, delMissing)
	if dr0.Code != http.StatusPreconditionFailed {
		t.Fatalf("delete without if-match %d %s", dr0.Code, dr0.Body.String())
	}

	del := httptest.NewRequest(http.MethodDelete, "/api/v1/users/alice", nil)
	del.Header.Set("Authorization", "Bearer "+testToken)
	del.Header.Set("If-Match", next)
	dr := httptest.NewRecorder()
	h.ServeHTTP(dr, del)
	if dr.Code != http.StatusNoContent {
		t.Fatalf("delete %d %s", dr.Code, dr.Body.String())
	}
	if dr.Body.Len() != 0 {
		t.Fatalf("delete body %q", dr.Body.String())
	}

	gone := httptest.NewRequest(http.MethodGet, "/api/v1/users/alice", nil)
	gone.Header.Set("Authorization", "Bearer "+testToken)
	g2 := httptest.NewRecorder()
	h.ServeHTTP(g2, gone)
	if g2.Code != http.StatusNotFound {
		t.Fatalf("get after delete %d %s", g2.Code, g2.Body.String())
	}
}

func TestUserScopes(t *testing.T) {
	t.Parallel()
	s, _, _ := directoryServer(t)
	h := s.Handler()

	unauth := httptest.NewRequest(http.MethodGet, "/api/v1/users", nil)
	ur := httptest.NewRecorder()
	h.ServeHTTP(ur, unauth)
	if ur.Code != http.StatusUnauthorized {
		t.Fatalf("unauth %d", ur.Code)
	}

	writeList := httptest.NewRequest(http.MethodGet, "/api/v1/users", nil)
	writeList.Header.Set("Authorization", "Bearer "+writeOnlyToken)
	wlr := httptest.NewRecorder()
	h.ServeHTTP(wlr, writeList)
	if wlr.Code != http.StatusForbidden {
		t.Fatalf("write-only list %d %s", wlr.Code, wlr.Body.String())
	}

	readCreate := httptest.NewRequest(http.MethodPost, "/api/v1/users", strings.NewReader(`{"id":"bob","password":"`+userPass+`"}`))
	readCreate.Header.Set("Authorization", "Bearer "+readOnlyToken)
	readCreate.Header.Set("Content-Type", "application/json")
	rcr := httptest.NewRecorder()
	h.ServeHTTP(rcr, readCreate)
	if rcr.Code != http.StatusForbidden {
		t.Fatalf("read-only create %d %s", rcr.Code, rcr.Body.String())
	}

	create := httptest.NewRequest(http.MethodPost, "/api/v1/users", strings.NewReader(`{"id":"bob","password":"`+userPass+`"}`))
	create.Header.Set("Authorization", "Bearer "+writeOnlyToken)
	create.Header.Set("Content-Type", "application/json")
	cr := httptest.NewRecorder()
	h.ServeHTTP(cr, create)
	if cr.Code != http.StatusCreated {
		t.Fatalf("write-only create %d %s", cr.Code, cr.Body.String())
	}
}

func TestPasswordEnableDisableAndUserGroups(t *testing.T) {
	t.Parallel()
	s, users, groups := directoryServer(t)
	h := s.Handler()

	create := httptest.NewRequest(http.MethodPost, "/api/v1/users", strings.NewReader(`{"id":"carol","password":"`+userPass+`"}`))
	create.Header.Set("Authorization", "Bearer "+testToken)
	create.Header.Set("Content-Type", "application/json")
	cr := httptest.NewRecorder()
	h.ServeHTTP(cr, create)
	if cr.Code != http.StatusCreated {
		t.Fatalf("create %d %s", cr.Code, cr.Body.String())
	}
	var created generated.User
	decodeOpenAPI(t, cr, &created)
	etag := cr.Header().Get("ETag")

	writePW := httptest.NewRequest(http.MethodPost, "/api/v1/users/carol/password", strings.NewReader(`{"password":"lab-new-password-99","revision":"`+created.Revision+`"}`))
	writePW.Header.Set("Authorization", "Bearer "+writeOnlyToken)
	writePW.Header.Set("Content-Type", "application/json")
	wpr := httptest.NewRecorder()
	h.ServeHTTP(wpr, writePW)
	if wpr.Code != http.StatusForbidden {
		t.Fatalf("write-only password %d %s", wpr.Code, wpr.Body.String())
	}
	assertProblem(t, wpr, "auth")
	if users.passwords[directory.UserID("carol")] != userPass {
		t.Fatal("password changed without password scope")
	}

	setPW := httptest.NewRequest(http.MethodPost, "/api/v1/users/carol/password", strings.NewReader(`{"password":"lab-new-password-99","revision":"`+created.Revision+`"}`))
	setPW.Header.Set("Authorization", "Bearer "+passwordOnlyToken)
	setPW.Header.Set("Content-Type", "application/json")
	spr := httptest.NewRecorder()
	h.ServeHTTP(spr, setPW)
	if spr.Code != http.StatusNoContent {
		t.Fatalf("set password %d %s", spr.Code, spr.Body.String())
	}
	if spr.Body.Len() != 0 {
		t.Fatalf("password body %q", spr.Body.String())
	}
	mustPW := httptest.NewRequest(http.MethodPost, "/api/v1/users/carol/password", strings.NewReader(`{"password":"lab-new-password-99","revision":"`+created.Revision+`","mustChange":true}`))
	mustPW.Header.Set("Authorization", "Bearer "+passwordOnlyToken)
	mustPW.Header.Set("Content-Type", "application/json")
	mpr := httptest.NewRecorder()
	h.ServeHTTP(mpr, mustPW)
	if mpr.Code != http.StatusNoContent {
		t.Fatalf("set password mustChange %d %s", mpr.Code, mpr.Body.String())
	}
	if !users.mustChange[directory.UserID("carol")] {
		t.Fatal("mustChange should stamp expire after set password")
	}
	assertNoSecret(t, spr.Body.String(), "lab-new-password-99", userPass)
	if users.passwords[directory.UserID("carol")] != "lab-new-password-99" {
		t.Fatalf("stored password %q", users.passwords[directory.UserID("carol")])
	}

	dis := httptest.NewRequest(http.MethodPost, "/api/v1/users/carol/disable", nil)
	dis.Header.Set("Authorization", "Bearer "+testToken)
	dis.Header.Set("If-Match", etag)
	drec := httptest.NewRecorder()
	h.ServeHTTP(drec, dis)
	if drec.Code != http.StatusOK {
		t.Fatalf("disable %d %s", drec.Code, drec.Body.String())
	}
	var disabled generated.User
	decodeOpenAPI(t, drec, &disabled)
	if disabled.Enabled {
		t.Fatal("expected disabled")
	}
	assertNoSecret(t, drec.Body.String(), userPass, "lab-new-password-99")
	enETag := drec.Header().Get("ETag")

	en := httptest.NewRequest(http.MethodPost, "/api/v1/users/carol/enable", nil)
	en.Header.Set("Authorization", "Bearer "+testToken)
	en.Header.Set("If-Match", enETag)
	erec := httptest.NewRecorder()
	h.ServeHTTP(erec, en)
	if erec.Code != http.StatusOK {
		t.Fatalf("enable %d %s", erec.Code, erec.Body.String())
	}
	var enabled generated.User
	decodeOpenAPI(t, erec, &enabled)
	if !enabled.Enabled {
		t.Fatal("expected enabled")
	}

	exp := httptest.NewRequest(http.MethodPost, "/api/v1/users/carol/expire-password", nil)
	exp.Header.Set("Authorization", "Bearer "+passwordOnlyToken)
	exp.Header.Set("If-Match", erec.Header().Get("ETag"))
	exprec := httptest.NewRecorder()
	h.ServeHTTP(exprec, exp)
	if exprec.Code != http.StatusOK {
		t.Fatalf("expire %d %s", exprec.Code, exprec.Body.String())
	}
	var expired generated.AccountState
	decodeOpenAPI(t, exprec, &expired)
	if !expired.MustChange {
		t.Fatalf("expire state %+v", expired)
	}

	lock := httptest.NewRequest(http.MethodPost, "/api/v1/users/carol/lock", nil)
	lock.Header.Set("Authorization", "Bearer "+testToken)
	lock.Header.Set("If-Match", erec.Header().Get("ETag"))
	lockrec := httptest.NewRecorder()
	h.ServeHTTP(lockrec, lock)
	if lockrec.Code != http.StatusOK {
		t.Fatalf("lock %d %s", lockrec.Code, lockrec.Body.String())
	}
	var locked generated.AccountState
	decodeOpenAPI(t, lockrec, &locked)
	if !locked.Locked {
		t.Fatalf("lock state %+v", locked)
	}

	st := httptest.NewRequest(http.MethodGet, "/api/v1/users/carol/account-state", nil)
	st.Header.Set("Authorization", "Bearer "+testToken)
	strec := httptest.NewRecorder()
	h.ServeHTTP(strec, st)
	if strec.Code != http.StatusOK {
		t.Fatalf("account-state %d %s", strec.Code, strec.Body.String())
	}

	noMatch := httptest.NewRequest(http.MethodPost, "/api/v1/users/carol/disable", nil)
	noMatch.Header.Set("Authorization", "Bearer "+testToken)
	nmr := httptest.NewRecorder()
	h.ServeHTTP(nmr, noMatch)
	if nmr.Code != http.StatusPreconditionFailed {
		t.Fatalf("enable/disable without If-Match %d %s", nmr.Code, nmr.Body.String())
	}

	users.mu.Lock()
	u := users.byID["carol"]
	u.Groups = []directory.GroupID{"staff", "gone"}
	users.put(u)
	users.mu.Unlock()
	groups.mu.Lock()
	groups.put(directory.Group{ID: "staff", Members: []directory.MemberRef{{Kind: "user", ID: "carol"}}})
	groups.mu.Unlock()

	lg := httptest.NewRequest(http.MethodGet, "/api/v1/users/carol/groups", nil)
	lg.Header.Set("Authorization", "Bearer "+readOnlyToken)
	lgr := httptest.NewRecorder()
	h.ServeHTTP(lgr, lg)
	if lgr.Code != http.StatusOK {
		t.Fatalf("user groups %d %s", lgr.Code, lgr.Body.String())
	}
	var gp generated.GroupPage
	decodeOpenAPI(t, lgr, &gp)
	if len(gp.Items) != 1 || gp.Items[0].Id != "staff" {
		t.Fatalf("stale group must be skipped: %+v", gp)
	}

	pwList := httptest.NewRequest(http.MethodGet, "/api/v1/users/carol/groups", nil)
	pwList.Header.Set("Authorization", "Bearer "+passwordOnlyToken)
	plr := httptest.NewRecorder()
	h.ServeHTTP(plr, pwList)
	if plr.Code != http.StatusForbidden {
		t.Fatalf("password-only list groups %d %s", plr.Code, plr.Body.String())
	}
}

func TestUsersUnavailableWithoutService(t *testing.T) {
	t.Parallel()
	s := testServer(t, nil)
	req := httptest.NewRequest(http.MethodGet, "/api/v1/users", nil)
	req.Header.Set("Authorization", "Bearer "+testToken)
	rec := httptest.NewRecorder()
	s.Handler().ServeHTTP(rec, req)
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("status %d %s", rec.Code, rec.Body.String())
	}
	assertProblem(t, rec, "directory")
}

func decodeOpenAPI(t *testing.T, rec *httptest.ResponseRecorder, dst any) {
	t.Helper()
	dec := json.NewDecoder(strings.NewReader(rec.Body.String()))
	dec.DisallowUnknownFields()
	if err := dec.Decode(dst); err != nil {
		t.Fatalf("openapi: %v %s", err, rec.Body.String())
	}
}

func TestPasswordBodiesRedactOnDebug(t *testing.T) {
	t.Parallel()
	create := userSpecBody{ID: "alice", Password: observability.Secret(userPass)}
	set := passwordBody{Password: observability.Secret(userPass), Revision: "abc"}
	for _, s := range []string{fmt.Sprintf("%v", create), fmt.Sprintf("%+v", create), fmt.Sprintf("%#v", create), fmt.Sprintf("%v", set), fmt.Sprintf("%+v", set)} {
		if strings.Contains(s, userPass) {
			t.Fatalf("password in debug serialization: %s", s)
		}
	}
	raw, err := json.Marshal(create)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(raw), userPass) {
		t.Fatalf("password in json: %s", raw)
	}
}

func assertNoSecret(t *testing.T, body string, secrets ...string) {
	t.Helper()
	lower := strings.ToLower(body)
	if strings.Contains(lower, "userpassword") {
		t.Fatalf("userPassword in body: %s", body)
	}
	for _, s := range secrets {
		if s != "" && strings.Contains(body, s) {
			t.Fatalf("secret %q leaked: %s", s, body)
		}
	}
}
