package api

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/hilather/go-lab-ldap-mcp/internal/app"
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
		{method: http.MethodGet, path: "/api/v1/users/suite/groups", scope: auth.ScopeDirectoryRead},
		{method: http.MethodGet, path: "/api/v1/groups", scope: auth.ScopeDirectoryRead},
		{method: http.MethodPost, path: "/api/v1/groups", scope: auth.ScopeDirectoryWrite, mutate: true, body: grp},
		{method: http.MethodGet, path: "/api/v1/groups/suiteg", scope: auth.ScopeDirectoryRead},
		{method: http.MethodDelete, path: "/api/v1/groups/suiteg", scope: auth.ScopeDirectoryWrite, mutate: true},
		{method: http.MethodPost, path: "/api/v1/groups/suiteg/members", scope: auth.ScopeDirectoryWrite, mutate: true, body: members},
		{method: http.MethodDelete, path: "/api/v1/groups/suiteg/members", scope: auth.ScopeDirectoryWrite, mutate: true, body: members},
		{method: http.MethodPut, path: "/api/v1/groups/suiteg/members", scope: auth.ScopeDirectoryWrite, mutate: true, body: members},
		{method: http.MethodPost, path: "/api/v1/search", scope: auth.ScopeDirectoryRead, body: search},
		{method: http.MethodPost, path: "/api/v1/auth-tests", scope: auth.ScopeDirectoryPassword, body: bind},
		{method: http.MethodGet, path: "/api/v1/rootdse", scope: auth.ScopeSchemaRead},
		{method: http.MethodGet, path: "/api/v1/schema", scope: auth.ScopeSchemaRead},
		{method: http.MethodGet, path: "/api/v1/schema/objectclasses/inetOrgPerson", scope: auth.ScopeSchemaRead},
		{method: http.MethodGet, path: "/api/v1/schema/attributes/uid", scope: auth.ScopeSchemaRead},
	}
}

func TestRESTScopeMatrixAndReadOnlyCannotMutate(t *testing.T) {
	t.Parallel()
	users := newMemUsers()
	groups := newMemGroups()
	svc := app.New(app.Deps{
		Users:            users,
		Groups:           groups,
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
			auth.ScopeSchemaRead, auth.ScopeAuditRead,
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
		System:         svc.Query,
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
	if tc.method == http.MethodPatch || tc.method == http.MethodDelete || strings.Contains(tc.path, "/members") || strings.Contains(tc.path, "/enable") || strings.Contains(tc.path, "/disable") {
		req.Header.Set("If-Match", `"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"`)
	}
	return req
}
