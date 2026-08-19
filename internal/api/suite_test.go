package api

import (
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/hilather/go-lab-ldap-mcp/internal/app"
	"github.com/hilather/go-lab-ldap-mcp/internal/audit"
	"github.com/hilather/go-lab-ldap-mcp/internal/auth"
	"github.com/hilather/go-lab-ldap-mcp/internal/directory"
	"github.com/hilather/go-lab-ldap-mcp/internal/observability"
)

// T-075: every implemented operation has positive and negative authn/authz.
// A read-only token cannot mutate any route.

type suiteCase struct {
	method string
	path   string
	body   string
	scope  string
	mutate bool
	public bool
}

func restSuite() []suiteCase {
	userBody := `{"id":"suite","password":"lab-suite-password-12"}`
	patch := `{"attributes":{"sn":"X"}}`
	pw := `{"password":"lab-suite-password-99","revision":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}`
	grp := `{"id":"suiteg","members":[{"kind":"user","id":"suite"}]}`
	members := `{"members":[{"kind":"user","id":"suite"}]}`
	search := `{"filter":"(uid=suite)"}`
	bind := `{"identity":"suite","password":"lab-suite-password-12","transport":"ldaps"}`
	return []suiteCase{
		{method: http.MethodGet, path: "/health", public: true},
		{method: http.MethodGet, path: "/health/ready", public: true},
		{method: http.MethodGet, path: "/metrics", public: true},
		{method: http.MethodGet, path: "/api/v1/version", scope: auth.ScopeDirectoryRead},
		{method: http.MethodGet, path: "/api/v1/capabilities", scope: auth.ScopeDirectoryRead},
		{method: http.MethodGet, path: "/api/v1/baseline", scope: auth.ScopeDirectoryRead},
		{method: http.MethodGet, path: "/api/v1/diagnostics"},
		{method: http.MethodGet, path: "/api/v1/audit", scope: auth.ScopeAuditRead},
		{method: http.MethodGet, path: "/api/v1/users", scope: auth.ScopeDirectoryRead},
		{method: http.MethodPost, path: "/api/v1/users", scope: auth.ScopeDirectoryWrite, mutate: true, body: userBody},
		{method: http.MethodGet, path: "/api/v1/users/suite", scope: auth.ScopeDirectoryRead},
		{method: http.MethodPatch, path: "/api/v1/users/suite", scope: auth.ScopeDirectoryWrite, mutate: true, body: patch},
		{method: http.MethodDelete, path: "/api/v1/users/suite", scope: auth.ScopeDirectoryWrite, mutate: true},
		{method: http.MethodPost, path: "/api/v1/users/suite/password", scope: auth.ScopeDirectoryPassword, mutate: true, body: pw},
		{method: http.MethodPost, path: "/api/v1/users/suite/enable", scope: auth.ScopeDirectoryWrite, mutate: true},
		{method: http.MethodPost, path: "/api/v1/users/suite/disable", scope: auth.ScopeDirectoryWrite, mutate: true},
		{method: http.MethodGet, path: "/api/v1/users/suite/account-state", scope: auth.ScopeDirectoryRead},
		{method: http.MethodPost, path: "/api/v1/users/suite/expire-password", scope: auth.ScopeDirectoryPassword, mutate: true},
		{method: http.MethodPost, path: "/api/v1/users/suite/clear-password-expiry", scope: auth.ScopeDirectoryPassword, mutate: true},
		{method: http.MethodPost, path: "/api/v1/users/suite/lock", scope: auth.ScopeDirectoryWrite, mutate: true},
		{method: http.MethodPost, path: "/api/v1/users/suite/unlock", scope: auth.ScopeDirectoryWrite, mutate: true},
		{method: http.MethodGet, path: "/api/v1/users/suite/groups", scope: auth.ScopeDirectoryRead},
		{method: http.MethodGet, path: "/api/v1/groups", scope: auth.ScopeDirectoryRead},
		{method: http.MethodPost, path: "/api/v1/groups", scope: auth.ScopeDirectoryWrite, mutate: true, body: grp},
		{method: http.MethodGet, path: "/api/v1/groups/suiteg", scope: auth.ScopeDirectoryRead},
		{method: http.MethodDelete, path: "/api/v1/groups/suiteg", scope: auth.ScopeDirectoryWrite, mutate: true},
		{method: http.MethodPost, path: "/api/v1/groups/suiteg/members", scope: auth.ScopeDirectoryWrite, mutate: true, body: members},
		{method: http.MethodDelete, path: "/api/v1/groups/suiteg/members", scope: auth.ScopeDirectoryWrite, mutate: true, body: members},
		{method: http.MethodPut, path: "/api/v1/groups/suiteg/members", scope: auth.ScopeDirectoryWrite, mutate: true, body: members},
		{method: http.MethodPost, path: "/api/v1/search", scope: auth.ScopeDirectoryRead, body: search},
		{method: http.MethodGet, path: "/api/v1/suffixes", scope: auth.ScopeDirectoryRead},
		{method: http.MethodPost, path: "/api/v1/tree", scope: auth.ScopeDirectoryRead, body: `{"base":"dc=example,dc=test"}`},
		{method: http.MethodGet, path: "/api/v1/entries?dn=ou=people,dc=example,dc=test", scope: auth.ScopeDirectoryRead},
		{method: http.MethodPost, path: "/api/v1/entries", scope: auth.ScopeDirectoryWrite, mutate: true, body: `{"dn":"ou=lab,ou=people,dc=example,dc=test","objectClasses":["organizationalUnit"]}`},
		{method: http.MethodPatch, path: "/api/v1/entries?dn=ou=lab,ou=people,dc=example,dc=test", scope: auth.ScopeDirectoryWrite, mutate: true, body: `{"changes":[{"op":"replace","name":"description","values":["x"]}]}`},
		{method: http.MethodDelete, path: "/api/v1/entries?dn=ou=lab,ou=people,dc=example,dc=test&confirm=true", scope: auth.ScopeDirectoryWrite, mutate: true},
		{method: http.MethodPost, path: "/api/v1/entries/move", scope: auth.ScopeDirectoryWrite, mutate: true, body: `{"dn":"ou=lab,ou=people,dc=example,dc=test","newDN":"ou=lab2,ou=people,dc=example,dc=test"}`},
		{method: http.MethodPost, path: "/api/v1/auth-tests", scope: auth.ScopeDirectoryPassword, body: bind},
		{method: http.MethodGet, path: "/api/v1/rootdse", scope: auth.ScopeSchemaRead},
		{method: http.MethodGet, path: "/api/v1/schema", scope: auth.ScopeSchemaRead},
		{method: http.MethodGet, path: "/api/v1/schema/objectclasses/inetOrgPerson", scope: auth.ScopeSchemaRead},
		{method: http.MethodGet, path: "/api/v1/schema/attributes/uid", scope: auth.ScopeSchemaRead},
		{method: http.MethodPost, path: "/api/v1/reset", scope: auth.ScopeLabReset, mutate: true, body: `{"name":"lab","expectedRevision":"aaa"}`},
		{method: http.MethodGet, path: "/api/v1/reset", scope: auth.ScopeLabReset},
		{method: http.MethodGet, path: "/api/v1/export", scope: auth.ScopeLabExport},
	}
}

func TestRESTScopeMatrixAndReadOnlyCannotMutate(t *testing.T) {
	t.Parallel()
	users := newMemUsers()
	groups := newMemGroups()
	svc := app.New(app.Deps{
		Users:            users,
		Groups:           groups,
		Entries:          newMemEntries(),
		Search:           newMemSearch(),
		Bind:             newMemBind(),
		Schema:           newMemSchema(),
		Caps:             stubCaps{caps: testCaps()},
		Marker:           stubMarker{m: directory.BaselineMarker{AppliedRevision: "aaa"}},
		ExpectedRevision: "aaa",
		PeopleDN:         "ou=people,dc=example,dc=test",
		GroupsDN:         "ou=groups,dc=example,dc=test",
	})
	read := "lab-suite-read-only-token-32xxxx"
	reg, err := auth.NewRegistry([]auth.Token{
		{ID: "admin", Scopes: []string{
			auth.ScopeDirectoryRead, auth.ScopeDirectoryWrite, auth.ScopeDirectoryPassword,
			auth.ScopeSchemaRead, auth.ScopeAuditRead, auth.ScopeLabReset, auth.ScopeLabExport,
		}, Secret: observability.Secret(testToken)},
		{ID: "reader", Scopes: []string{auth.ScopeDirectoryRead}, Secret: observability.Secret(read)},
	})
	if err != nil {
		t.Fatal(err)
	}
	s, err := New(Options{
		Registry:       reg,
		Sessions:       auth.NewStore(auth.DefaultSessionConfig()),
		Ready:          func() bool { return true },
		Users:          svc.Users,
		Groups:         svc.Groups,
		Query:          svc.Query,
		Entries:        svc.Entries,
		System:         svc.Query,
		Reset:          svc.Reset,
		Export:         svc.Export,
		MetricsEnabled: true,
		Metrics:        observability.NewRegistry(observability.CurrentBuild("labldap")),
		CursorKey:      mustCursorKey(t),
		Diagnostics:    func() app.Diagnostics { return app.Diagnostics{Reset: app.ResetHint{State: "Ready"}} },
	})
	if err != nil {
		t.Fatal(err)
	}
	h := s.Handler()

	for _, tc := range restSuite() {
		// Unauthenticated
		unauth := suiteRequest(tc, "")
		ur := httptest.NewRecorder()
		h.ServeHTTP(ur, unauth)
		if tc.public {
			if ur.Code == http.StatusUnauthorized || ur.Code == http.StatusForbidden {
				t.Fatalf("%s %s public got %d %s", tc.method, tc.path, ur.Code, ur.Body.String())
			}
		} else if ur.Code != http.StatusUnauthorized {
			t.Fatalf("%s %s unauth %d %s", tc.method, tc.path, ur.Code, ur.Body.String())
		}
		assertNoSecret(t, ur.Body.String(), testToken, read, "lab-suite-password-12", "lab-suite-password-99")

		// Read-only token
		ro := suiteRequest(tc, read)
		rr := httptest.NewRecorder()
		h.ServeHTTP(rr, ro)
		if tc.public {
			continue
		}
		if tc.mutate || (tc.scope != "" && tc.scope != auth.ScopeDirectoryRead) {
			if rr.Code != http.StatusForbidden && rr.Code != http.StatusUnauthorized {
				t.Fatalf("read-only mutate/scope %s %s = %d %s", tc.method, tc.path, rr.Code, rr.Body.String())
			}
		}
		if tc.mutate && rr.Code != http.StatusForbidden {
			t.Fatalf("read-only must not mutate %s %s = %d %s", tc.method, tc.path, rr.Code, rr.Body.String())
		}
		assertNoSecret(t, rr.Body.String(), testToken, read, "lab-suite-password-12")

		// Positive: admin
		ok := suiteRequest(tc, testToken)
		or := httptest.NewRecorder()
		h.ServeHTTP(or, ok)
		if or.Code == http.StatusUnauthorized || or.Code == http.StatusForbidden {
			t.Fatalf("admin denied %s %s = %d %s", tc.method, tc.path, or.Code, or.Body.String())
		}
		assertNoSecret(t, or.Body.String(), testToken, read, "lab-suite-password-12", "lab-suite-password-99")
	}
}

func suiteRequest(tc suiteCase, token string) *http.Request {
	var body io.Reader
	if tc.body != "" {
		body = strings.NewReader(tc.body)
	}
	req := httptest.NewRequest(tc.method, tc.path, body)
	if tc.body != "" {
		req.Header.Set("Content-Type", "application/json")
	}
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	if tc.method == http.MethodPatch || tc.method == http.MethodDelete || strings.Contains(tc.path, "/members") || strings.Contains(tc.path, "/entries/move") || strings.Contains(tc.path, "/enable") || strings.Contains(tc.path, "/disable") || strings.Contains(tc.path, "/expire-password") || strings.Contains(tc.path, "/clear-password-expiry") || strings.Contains(tc.path, "/lock") || strings.Contains(tc.path, "/unlock") {
		req.Header.Set("If-Match", `"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"`)
	}
	return req
}

func TestSessionAuthnCSRFAndReadOnlyLogin(t *testing.T) {
	t.Parallel()
	s, _, _ := directoryServer(t)
	h := s.Handler()

	unauthGet := httptest.NewRequest(http.MethodGet, "/api/v1/session", nil)
	ug := httptest.NewRecorder()
	h.ServeHTTP(ug, unauthGet)
	if ug.Code != http.StatusUnauthorized {
		t.Fatalf("get unauth %d %s", ug.Code, ug.Body.String())
	}

	unauthDel := httptest.NewRequest(http.MethodDelete, "/api/v1/session", nil)
	ud := httptest.NewRecorder()
	h.ServeHTTP(ud, unauthDel)
	if ud.Code != http.StatusUnauthorized {
		t.Fatalf("delete unauth %d %s", ud.Code, ud.Body.String())
	}

	login := httptest.NewRequest(http.MethodPost, "/api/v1/session", strings.NewReader(`{"token":"`+readOnlyToken+`"}`))
	login.Header.Set("Content-Type", "application/json")
	lr := httptest.NewRecorder()
	h.ServeHTTP(lr, login)
	if lr.Code != http.StatusOK {
		t.Fatalf("read-only login %d %s", lr.Code, lr.Body.String())
	}
	c := cookieNamed(lr.Result(), auth.CookieName)
	if c == nil {
		t.Fatal("cookie")
	}
	var created sessionCreatedBody
	if err := json.Unmarshal(lr.Body.Bytes(), &created); err != nil {
		t.Fatal(err)
	}

	missingCSRF := httptest.NewRequest(http.MethodDelete, "/api/v1/session", nil)
	missingCSRF.Host = "127.0.0.1:8443"
	missingCSRF.Header.Set("Origin", "http://127.0.0.1:8443")
	missingCSRF.AddCookie(auth.NewSessionCookie(c.Value, false, 0))
	mr := httptest.NewRecorder()
	h.ServeHTTP(mr, missingCSRF)
	if mr.Code != http.StatusForbidden {
		t.Fatalf("missing csrf %d %s", mr.Code, mr.Body.String())
	}

	del := httptest.NewRequest(http.MethodDelete, "/api/v1/session", nil)
	del.Host = "127.0.0.1:8443"
	del.Header.Set("Origin", "http://127.0.0.1:8443")
	del.Header.Set(auth.CSRFHeader, created.CSRFToken)
	del.AddCookie(auth.NewSessionCookie(c.Value, false, 0))
	dr := httptest.NewRecorder()
	h.ServeHTTP(dr, del)
	if dr.Code != http.StatusNoContent {
		t.Fatalf("logout %d %s", dr.Code, dr.Body.String())
	}
	assertNoSecret(t, lr.Body.String()+dr.Body.String(), readOnlyToken, testToken, c.Value)
}

func TestRepresentativeHandlerLogsHaveNoSecrets(t *testing.T) {
	t.Parallel()
	users := newMemUsers()
	groups := newMemGroups()
	logs := &captureHandler{}
	svc := app.New(app.Deps{
		Users:            users,
		Groups:           groups,
		Entries:          newMemEntries(),
		Search:           newMemSearch(),
		Bind:             newMemBind(),
		Schema:           newMemSchema(),
		Caps:             stubCaps{caps: testCaps()},
		Marker:           stubMarker{m: directory.BaselineMarker{AppliedRevision: "aaa"}},
		ExpectedRevision: "aaa",
	})
	reg, err := auth.NewRegistry([]auth.Token{
		{ID: "admin", Scopes: []string{auth.ScopeDirectoryRead, auth.ScopeDirectoryWrite, auth.ScopeDirectoryPassword, auth.ScopeAuditRead}, Secret: observability.Secret(testToken)},
		{ID: "reader", Scopes: []string{auth.ScopeDirectoryRead}, Secret: observability.Secret(readOnlyToken)},
	})
	if err != nil {
		t.Fatal(err)
	}
	s, err := New(Options{
		Registry:  reg,
		Sessions:  auth.NewStore(auth.DefaultSessionConfig()),
		Users:     svc.Users,
		Groups:    svc.Groups,
		Query:     svc.Query,
		Entries:   svc.Entries,
		System:    svc.Query,
		Logger:    slog.New(logs),
		AuditHook: &audit.Memory{},
		CursorKey: mustCursorKey(t),
	})
	if err != nil {
		t.Fatal(err)
	}
	h := s.Handler()

	login := httptest.NewRequest(http.MethodPost, "/api/v1/session", strings.NewReader(`{"token":"`+testToken+`"}`))
	login.Header.Set("Content-Type", "application/json")
	login.Header.Set("Authorization", "Bearer "+testToken)
	lr := httptest.NewRecorder()
	h.ServeHTTP(lr, login)
	cookie := ""
	if c := cookieNamed(lr.Result(), auth.CookieName); c != nil {
		cookie = c.Value
	}

	create := httptest.NewRequest(http.MethodPost, "/api/v1/users", strings.NewReader(`{"id":"loguser","password":"`+userPass+`"}`))
	create.Header.Set("Authorization", "Bearer "+testToken)
	create.Header.Set("Content-Type", "application/json")
	h.ServeHTTP(httptest.NewRecorder(), create)

	bind := httptest.NewRequest(http.MethodPost, "/api/v1/auth-tests", strings.NewReader(`{"identity":"loguser","password":"`+userPass+`","transport":"ldaps"}`))
	bind.Header.Set("Authorization", "Bearer "+testToken)
	bind.Header.Set("Content-Type", "application/json")
	h.ServeHTTP(httptest.NewRecorder(), bind)

	deny := httptest.NewRequest(http.MethodPost, "/api/v1/users", strings.NewReader(`{"id":"x","password":"`+userPass+`"}`))
	deny.Header.Set("Authorization", "Bearer "+readOnlyToken)
	deny.Header.Set("Content-Type", "application/json")
	h.ServeHTTP(httptest.NewRecorder(), deny)

	findings, err := observability.ScanReader(strings.NewReader(logs.String()), testToken, readOnlyToken, userPass, cookie)
	if err != nil {
		t.Fatal(err)
	}
	if len(findings) != 0 {
		t.Fatalf("handler logs leaked: %s\n%s", observability.ReportFindings(findings), logs.String())
	}
}
