package api

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/hilather/go-lab-ldap-mcp/api/generated"
	"github.com/hilather/go-lab-ldap-mcp/internal/app"
	"github.com/hilather/go-lab-ldap-mcp/internal/apperr"
	"github.com/hilather/go-lab-ldap-mcp/internal/auth"
	"github.com/hilather/go-lab-ldap-mcp/internal/config"
	"github.com/hilather/go-lab-ldap-mcp/internal/directory"
	"github.com/hilather/go-lab-ldap-mcp/internal/observability"
)

const (
	schemaOnlyToken = "lab-test-schema-only-token-32xx"
	bindPass        = "lab-bind-test-password-12"
)

type recordLimiter struct {
	mu   sync.Mutex
	keys []string
	deny map[string]bool
}

func (l *recordLimiter) Allow(key string) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.keys = append(l.keys, key)
	return l.deny == nil || !l.deny[key]
}

type captureHandler struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (h *captureHandler) Enabled(context.Context, slog.Level) bool { return true }

func (h *captureHandler) Handle(_ context.Context, r slog.Record) error {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.buf.WriteString(r.Message)
	r.Attrs(func(a slog.Attr) bool {
		h.buf.WriteByte(' ')
		h.buf.WriteString(a.String())
		return true
	})
	h.buf.WriteByte('\n')
	return nil
}

func (h *captureHandler) WithAttrs([]slog.Attr) slog.Handler { return h }
func (h *captureHandler) WithGroup(string) slog.Handler      { return h }

func (h *captureHandler) String() string {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.buf.String()
}

func queryServer(t *testing.T) (*Server, *memSearch, *memBind, *memSchema) {
	t.Helper()
	search := newMemSearch()
	search.page = directory.SearchPage{
		Entries: []directory.SearchEntry{{
			DN: "uid=alice,ou=people,dc=example,dc=test",
			Attributes: []directory.AttrKV{
				{Name: "uid", Value: "alice"},
				{Name: "userPassword", Value: bindPass},
				{Name: "nsslapd-rootpw", Value: "lab-root-secret-xx"},
			},
		}},
		NextCursor: "cursor-next",
	}
	bind := newMemBind()
	schema := newMemSchema()
	logs := &captureHandler{}
	svc := app.New(app.Deps{
		Search: search,
		Bind:   bind,
		Schema: schema,
	})
	reg, err := auth.NewRegistry([]auth.Token{
		{ID: "admin", Scopes: []string{auth.ScopeDirectoryRead, auth.ScopeDirectoryWrite, auth.ScopeDirectoryPassword, auth.ScopeSchemaRead}, Secret: observability.Secret(testToken)},
		{ID: "writer", Scopes: []string{auth.ScopeDirectoryWrite}, Secret: observability.Secret(writeOnlyToken)},
		{ID: "reader", Scopes: []string{auth.ScopeDirectoryRead}, Secret: observability.Secret(readOnlyToken)},
		{ID: "pw", Scopes: []string{auth.ScopeDirectoryPassword}, Secret: observability.Secret(passwordOnlyToken)},
		{ID: "schema", Scopes: []string{auth.ScopeSchemaRead}, Secret: observability.Secret(schemaOnlyToken)},
	})
	if err != nil {
		t.Fatal(err)
	}
	s, err := New(Options{
		Registry:        reg,
		Sessions:        auth.NewStore(auth.DefaultSessionConfig()),
		Logger:          slog.New(logs),
		Limiter:         &recordLimiter{},
		Query:           svc.Query,
		System:          svc.Query,
		PageSizeDefault: 50,
		PageSizeMax:     100,
		CursorKey:       config.NewCursorKey(),
	})
	if err != nil {
		t.Fatal(err)
	}
	s.log = slog.New(logs)
	return s, search, bind, schema
}

func TestSearchCursorAndDocumentedErrors(t *testing.T) {
	t.Parallel()
	s, search, _, _ := queryServer(t)
	h := s.Handler()

	ok := httptest.NewRequest(http.MethodPost, "/api/v1/search", strings.NewReader(`{"filter":"(uid=alice)","attributes":["uid"],"pageSize":10}`))
	ok.Header.Set("Authorization", "Bearer "+testToken)
	ok.Header.Set("Content-Type", "application/json")
	or := httptest.NewRecorder()
	h.ServeHTTP(or, ok)
	if or.Code != http.StatusOK {
		t.Fatalf("search %d %s", or.Code, or.Body.String())
	}
	if or.Header().Get("Cache-Control") != "no-store" {
		t.Fatal("search cache")
	}
	assertNoSecret(t, or.Body.String(), bindPass, "lab-root-secret-xx")
	var page generated.SearchPage
	decodeOpenAPI(t, or, &page)
	if len(page.Entries) != 1 || page.Entries[0].Dn == "" || page.NextCursor == nil || *page.NextCursor != "cursor-next" {
		t.Fatalf("page %+v", page)
	}
	if len(page.Entries[0].Attributes) != 1 || page.Entries[0].Attributes[0].Name != "uid" {
		t.Fatalf("redaction %+v", page.Entries[0].Attributes)
	}
	search.mu.Lock()
	got := search.last
	search.mu.Unlock()
	if got.Filter != "(uid=alice)" || got.PageSize != 10 || len(got.Attributes) != 1 {
		t.Fatalf("query %+v", got)
	}

	for _, tc := range []struct {
		name string
		body string
		path string
		code string
	}{
		{name: "empty filter", body: `{"filter":""}`, path: "filter", code: "empty"},
		{name: "missing filter", body: `{"base":"dc=example,dc=test"}`, path: "filter", code: "empty"},
		{name: "bad scope", body: `{"filter":"(uid=a)","scope":"tree"}`, path: "scope", code: "invalid"},
		{name: "page too large", body: `{"filter":"(uid=a)","pageSize":101}`, path: "pageSize", code: "too_large"},
		{name: "page invalid", body: `{"filter":"(uid=a)","pageSize":-1}`, path: "pageSize", code: "invalid"},
	} {
		req := httptest.NewRequest(http.MethodPost, "/api/v1/search", strings.NewReader(tc.body))
		req.Header.Set("Authorization", "Bearer "+testToken)
		req.Header.Set("Content-Type", "application/json")
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		if rec.Code != http.StatusBadRequest {
			t.Fatalf("%s status %d %s", tc.name, rec.Code, rec.Body.String())
		}
		assertProblem(t, rec, "configuration")
		assertField(t, rec, tc.path, tc.code)
	}

	search.err = apperr.New(apperr.CodeConfiguration, "search too broad").WithField(apperr.Field{
		Path: "filter", Code: "over_broad", Message: "filter is over-broad",
	})
	broad := httptest.NewRequest(http.MethodPost, "/api/v1/search", strings.NewReader(`{"filter":"(objectClass=*)"}`))
	broad.Header.Set("Authorization", "Bearer "+testToken)
	broad.Header.Set("Content-Type", "application/json")
	br := httptest.NewRecorder()
	h.ServeHTTP(br, broad)
	if br.Code != http.StatusBadRequest {
		t.Fatalf("over_broad %d %s", br.Code, br.Body.String())
	}
	assertField(t, br, "filter", "over_broad")

	search.err = apperr.New(apperr.CodeConfiguration, "cursor is invalid").WithField(apperr.Field{
		Path: "cursor", Code: "invalid", Message: "cursor is invalid",
	})
	cur := httptest.NewRequest(http.MethodPost, "/api/v1/search", strings.NewReader(`{"filter":"(uid=a)","cursor":"tampered"}`))
	cur.Header.Set("Authorization", "Bearer "+testToken)
	cur.Header.Set("Content-Type", "application/json")
	cr := httptest.NewRecorder()
	h.ServeHTTP(cr, cur)
	if cr.Code != http.StatusBadRequest {
		t.Fatalf("cursor %d %s", cr.Code, cr.Body.String())
	}
	assertField(t, cr, "cursor", "invalid")

	search.err = directory.Error("base", directory.FieldForbidden, "search base is outside configured roots")
	out := httptest.NewRequest(http.MethodPost, "/api/v1/search", strings.NewReader(`{"base":"dc=other","filter":"(uid=a)"}`))
	out.Header.Set("Authorization", "Bearer "+testToken)
	out.Header.Set("Content-Type", "application/json")
	xr := httptest.NewRecorder()
	h.ServeHTTP(xr, out)
	if xr.Code != http.StatusForbidden {
		t.Fatalf("boundary %d %s", xr.Code, xr.Body.String())
	}
	assertProblem(t, xr, "directory")
	assertField(t, xr, "base", directory.FieldForbidden)
}

func TestSearchScopes(t *testing.T) {
	t.Parallel()
	s, _, _, _ := queryServer(t)
	h := s.Handler()

	unauth := httptest.NewRequest(http.MethodPost, "/api/v1/search", strings.NewReader(`{"filter":"(uid=a)"}`))
	unauth.Header.Set("Content-Type", "application/json")
	ur := httptest.NewRecorder()
	h.ServeHTTP(ur, unauth)
	if ur.Code != http.StatusUnauthorized {
		t.Fatalf("unauth %d", ur.Code)
	}

	forbid := httptest.NewRequest(http.MethodPost, "/api/v1/search", strings.NewReader(`{"filter":"(uid=a)"}`))
	forbid.Header.Set("Authorization", "Bearer "+writeOnlyToken)
	forbid.Header.Set("Content-Type", "application/json")
	fr := httptest.NewRecorder()
	h.ServeHTTP(fr, forbid)
	if fr.Code != http.StatusForbidden {
		t.Fatalf("write-only %d %s", fr.Code, fr.Body.String())
	}

	pw := httptest.NewRequest(http.MethodPost, "/api/v1/search", strings.NewReader(`{"filter":"(uid=a)"}`))
	pw.Header.Set("Authorization", "Bearer "+passwordOnlyToken)
	pw.Header.Set("Content-Type", "application/json")
	pr := httptest.NewRecorder()
	h.ServeHTTP(pr, pw)
	if pr.Code != http.StatusForbidden {
		t.Fatalf("password-only %d %s", pr.Code, pr.Body.String())
	}
}

func TestBindTestDiagnosticNot401(t *testing.T) {
	t.Parallel()
	s, _, bind, _ := queryServer(t)
	h := s.Handler()

	req := httptest.NewRequest(http.MethodPost, "/api/v1/auth-tests", strings.NewReader(`{"identity":"alice","password":"`+bindPass+`","transport":"ldaps"}`))
	req.Header.Set("Authorization", "Bearer "+passwordOnlyToken)
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("invalid creds must be 200 diagnostic, got %d %s", rec.Code, rec.Body.String())
	}
	if rec.Header().Get("Cache-Control") != "no-store" {
		t.Fatal("bind-test cache")
	}
	assertNoSecret(t, rec.Body.String(), bindPass)
	var out generated.BindTestResult
	decodeOpenAPI(t, rec, &out)
	if out.Outcome != generated.InvalidCredentials {
		t.Fatalf("outcome %q", out.Outcome)
	}
	bind.mu.Lock()
	if bind.lastID != "alice" || bind.lastPW != bindPass || bind.lastT != directory.TransportLDAPS {
		t.Fatalf("bind args %+v", bind)
	}
	bind.mu.Unlock()

	bind.res = directory.BindTestResult{Outcome: directory.BindOutcomeSuccess}
	ok := httptest.NewRequest(http.MethodPost, "/api/v1/auth-tests", strings.NewReader(`{"identity":"alice","password":"`+bindPass+`"}`))
	ok.Header.Set("Authorization", "Bearer "+testToken)
	ok.Header.Set("Content-Type", "application/json")
	or := httptest.NewRecorder()
	h.ServeHTTP(or, ok)
	if or.Code != http.StatusOK {
		t.Fatalf("success %d %s", or.Code, or.Body.String())
	}
	var success generated.BindTestResult
	decodeOpenAPI(t, or, &success)
	if success.Outcome != generated.Success {
		t.Fatalf("success outcome %q", success.Outcome)
	}

	read := httptest.NewRequest(http.MethodPost, "/api/v1/auth-tests", strings.NewReader(`{"identity":"alice","password":"`+bindPass+`"}`))
	read.Header.Set("Authorization", "Bearer "+readOnlyToken)
	read.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, read)
	if rr.Code != http.StatusForbidden {
		t.Fatalf("read-only bind-test %d %s", rr.Code, rr.Body.String())
	}

	write := httptest.NewRequest(http.MethodPost, "/api/v1/auth-tests", strings.NewReader(`{"identity":"alice","password":"`+bindPass+`"}`))
	write.Header.Set("Authorization", "Bearer "+writeOnlyToken)
	write.Header.Set("Content-Type", "application/json")
	wr := httptest.NewRecorder()
	h.ServeHTTP(wr, write)
	if wr.Code != http.StatusForbidden {
		t.Fatalf("write-only bind-test %d %s", wr.Code, wr.Body.String())
	}

	unauth := httptest.NewRequest(http.MethodPost, "/api/v1/auth-tests", strings.NewReader(`{"identity":"alice","password":"`+bindPass+`"}`))
	unauth.Header.Set("Content-Type", "application/json")
	ur := httptest.NewRecorder()
	h.ServeHTTP(ur, unauth)
	if ur.Code != http.StatusUnauthorized {
		t.Fatalf("unauth %d", ur.Code)
	}

	emptyID := httptest.NewRequest(http.MethodPost, "/api/v1/auth-tests", strings.NewReader(`{"identity":"","password":"`+bindPass+`"}`))
	emptyID.Header.Set("Authorization", "Bearer "+passwordOnlyToken)
	emptyID.Header.Set("Content-Type", "application/json")
	er := httptest.NewRecorder()
	h.ServeHTTP(er, emptyID)
	if er.Code != http.StatusBadRequest {
		t.Fatalf("empty identity %d %s", er.Code, er.Body.String())
	}
	assertField(t, er, "identity", "empty")

	badT := httptest.NewRequest(http.MethodPost, "/api/v1/auth-tests", strings.NewReader(`{"identity":"alice","password":"`+bindPass+`","transport":"ftp"}`))
	badT.Header.Set("Authorization", "Bearer "+passwordOnlyToken)
	badT.Header.Set("Content-Type", "application/json")
	tr := httptest.NewRecorder()
	h.ServeHTTP(tr, badT)
	if tr.Code != http.StatusBadRequest {
		t.Fatalf("bad transport %d %s", tr.Code, tr.Body.String())
	}
	assertField(t, tr, "transport", "invalid")
}

func TestBindTestMustChangeIsDiagnostic(t *testing.T) {
	t.Parallel()
	s, _, bind, _ := queryServer(t)
	bind.mu.Lock()
	bind.res = directory.BindTestResult{Outcome: directory.BindOutcomeMustChange}
	bind.mu.Unlock()
	h := s.Handler()

	req := httptest.NewRequest(http.MethodPost, "/api/v1/auth-tests", strings.NewReader(`{"identity":"alice","password":"`+bindPass+`"}`))
	req.Header.Set("Authorization", "Bearer "+passwordOnlyToken)
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("must_change must be 200 diagnostic, got %d %s", rec.Code, rec.Body.String())
	}
	var out generated.BindTestResult
	decodeOpenAPI(t, rec, &out)
	if out.Outcome != generated.MustChange {
		t.Fatalf("outcome %q", out.Outcome)
	}
}

func TestBindTestRateLimitPerIPAndActor(t *testing.T) {
	t.Parallel()
	s, _, _, _ := queryServer(t)
	lim := &recordLimiter{deny: map[string]bool{"bind:ip:192.0.2.1": true}}
	s.limiter = lim
	req := httptest.NewRequest(http.MethodPost, "/api/v1/auth-tests", strings.NewReader(`{"identity":"alice","password":"`+bindPass+`"}`))
	req.Header.Set("Authorization", "Bearer "+passwordOnlyToken)
	req.Header.Set("Content-Type", "application/json")
	req.RemoteAddr = "192.0.2.1:1234"
	rec := httptest.NewRecorder()
	s.Handler().ServeHTTP(rec, req)
	if rec.Code != http.StatusTooManyRequests {
		t.Fatalf("ip limit %d %s", rec.Code, rec.Body.String())
	}
	assertProblem(t, rec, "auth")
	assertField(t, rec, "rateLimit", "rate_limited")

	s.limiter = &recordLimiter{deny: map[string]bool{"bind:actor:pw": true}}
	req = httptest.NewRequest(http.MethodPost, "/api/v1/auth-tests", strings.NewReader(`{"identity":"alice","password":"`+bindPass+`"}`))
	req.Header.Set("Authorization", "Bearer "+passwordOnlyToken)
	req.Header.Set("Content-Type", "application/json")
	rec = httptest.NewRecorder()
	s.Handler().ServeHTTP(rec, req)
	if rec.Code != http.StatusTooManyRequests {
		t.Fatalf("actor limit %d %s", rec.Code, rec.Body.String())
	}
}

func TestSearchAndBindTestBodiesExcludedFromLogs(t *testing.T) {
	t.Parallel()
	s, _, _, _ := queryServer(t)
	h := s.Handler()

	search := httptest.NewRequest(http.MethodPost, "/api/v1/search", strings.NewReader(`{"filter":"(userPassword=`+bindPass+`)"}`))
	search.Header.Set("Authorization", "Bearer "+testToken)
	search.Header.Set("Content-Type", "application/json")
	sr := httptest.NewRecorder()
	h.ServeHTTP(sr, search)
	if sr.Code != http.StatusOK {
		t.Fatalf("search %d %s", sr.Code, sr.Body.String())
	}

	bind := httptest.NewRequest(http.MethodPost, "/api/v1/auth-tests", strings.NewReader(`{"identity":"alice","password":"`+bindPass+`"}`))
	bind.Header.Set("Authorization", "Bearer "+passwordOnlyToken)
	bind.Header.Set("Content-Type", "application/json")
	br := httptest.NewRecorder()
	h.ServeHTTP(br, bind)
	if br.Code != http.StatusOK {
		t.Fatalf("bind %d %s", br.Code, br.Body.String())
	}

	logs := s.log.Handler().(*captureHandler).String()
	if strings.Contains(logs, bindPass) || strings.Contains(logs, "userPassword="+bindPass) {
		t.Fatalf("request body leaked to logs: %s", logs)
	}

	body := bindTestBody{Identity: "alice", Password: observability.Secret(bindPass), Transport: "ldaps"}
	for _, dumped := range []string{fmt.Sprintf("%v", body), fmt.Sprintf("%+v", body), fmt.Sprintf("%#v", body)} {
		if strings.Contains(dumped, bindPass) {
			t.Fatalf("password in debug serialization: %s", dumped)
		}
	}
	raw, err := json.Marshal(body)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(raw), bindPass) {
		t.Fatalf("password in json: %s", raw)
	}
}

func TestSearchUnavailableWithoutService(t *testing.T) {
	t.Parallel()
	s := testServer(t, nil)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/search", strings.NewReader(`{"filter":"(uid=a)"}`))
	req.Header.Set("Authorization", "Bearer "+testToken)
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	s.Handler().ServeHTTP(rec, req)
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("status %d %s", rec.Code, rec.Body.String())
	}
	assertProblem(t, rec, "directory")
}

func assertField(t *testing.T, rec *httptest.ResponseRecorder, path, code string) {
	t.Helper()
	var body generated.Problem
	decodeOpenAPI(t, rec, &body)
	if body.Errors == nil {
		t.Fatalf("missing errors in %s", rec.Body.String())
	}
	for _, f := range *body.Errors {
		if f.Path == path && f.Code == code {
			return
		}
	}
	t.Fatalf("want field %s/%s in %s", path, code, rec.Body.String())
}
