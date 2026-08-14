package api

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/hilather/go-lab-ldap-mcp/api/generated"
	"github.com/hilather/go-lab-ldap-mcp/internal/app"
	"github.com/hilather/go-lab-ldap-mcp/internal/auth"
	"github.com/hilather/go-lab-ldap-mcp/internal/directory"
	"github.com/hilather/go-lab-ldap-mcp/internal/observability"
)

const (
	writeOnlyToken = "lab-test-write-only-token-value-32"
	auditOnlyToken = "lab-test-audit-only-token-value-32"
)

type stubCaps struct {
	caps directory.Capabilities
	err  error
}

func (s stubCaps) Capabilities(context.Context) (directory.Capabilities, error) {
	return s.caps, s.err
}

type stubMarker struct {
	m   directory.BaselineMarker
	err error
}

func (s stubMarker) ReadMarker(context.Context) (directory.BaselineMarker, error) {
	return s.m, s.err
}

func testCaps() directory.Capabilities {
	return directory.Capabilities{
		EngineVendor:   "389 Project",
		EngineVersion:  "3.1.2",
		AdapterVersion: "test",
		Transports:     []string{"ldaps"},
		Plugins:        []string{"memberof"},
		PasswordScheme: "PBKDF2-SHA512",
		Controls:       []string{directory.ControlAssertionOID},
		RequiredOK:     true,
	}
}

func testQuery() *app.Query {
	return app.New(app.Deps{
		Caps: stubCaps{caps: testCaps()},
		Marker: stubMarker{m: directory.BaselineMarker{
			DN:              "cn=labldap-baseline,dc=example,dc=test",
			AppliedRevision: "aaa",
			ApplyVersion:    "dev",
			AppliedAt:       "2026-01-01T00:00:00Z",
		}},
		ExpectedRevision: "aaa",
		ControlRevision:  "bbb",
	}).Query
}

func systemServer(t *testing.T) *Server {
	t.Helper()
	reg, err := auth.NewRegistry([]auth.Token{
		{ID: "admin", Scopes: []string{auth.ScopeDirectoryRead, auth.ScopeDirectoryWrite}, Secret: observability.Secret(testToken)},
		{ID: "writer", Scopes: []string{auth.ScopeDirectoryWrite}, Secret: observability.Secret(writeOnlyToken)},
		{ID: "auditor", Scopes: []string{auth.ScopeAuditRead}, Secret: observability.Secret(auditOnlyToken)},
	})
	if err != nil {
		t.Fatal(err)
	}
	s, err := New(Options{
		Registry: reg,
		Sessions: auth.NewStore(auth.DefaultSessionConfig()),
		System:   testQuery(),
		Build: observability.BuildInfo{
			Version:   "dev",
			Revision:  "abc123",
			Time:      "2026-01-02T03:04:05Z",
			Component: "labldap",
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func TestVersionRequiresDirectoryRead(t *testing.T) {
	t.Parallel()
	s := systemServer(t)
	h := s.Handler()

	unauth := httptest.NewRequest(http.MethodGet, "/api/v1/version", nil)
	ur := httptest.NewRecorder()
	h.ServeHTTP(ur, unauth)
	if ur.Code != http.StatusUnauthorized {
		t.Fatalf("unauth %d %s", ur.Code, ur.Body.String())
	}
	assertProblem(t, ur, "auth")

	forbid := httptest.NewRequest(http.MethodGet, "/api/v1/version", nil)
	forbid.Header.Set("Authorization", "Bearer "+writeOnlyToken)
	fr := httptest.NewRecorder()
	h.ServeHTTP(fr, forbid)
	if fr.Code != http.StatusForbidden {
		t.Fatalf("write-only %d %s", fr.Code, fr.Body.String())
	}
	assertProblem(t, fr, "auth")

	ok := httptest.NewRequest(http.MethodGet, "/api/v1/version", nil)
	ok.Header.Set("Authorization", "Bearer "+testToken)
	or := httptest.NewRecorder()
	h.ServeHTTP(or, ok)
	if or.Code != http.StatusOK {
		t.Fatalf("ok %d %s", or.Code, or.Body.String())
	}
	if or.Header().Get("Cache-Control") != "no-store" {
		t.Fatalf("cache %q", or.Header().Get("Cache-Control"))
	}
	var info generated.BuildInfo
	dec := json.NewDecoder(strings.NewReader(or.Body.String()))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&info); err != nil {
		t.Fatalf("openapi: %v %s", err, or.Body.String())
	}
	if info.Version != "dev" || info.Revision != "abc123" || info.Time != "2026-01-02T03:04:05Z" || info.Component != "labldap" {
		t.Fatalf("%+v", info)
	}
	var raw map[string]any
	if err := json.Unmarshal(or.Body.Bytes(), &raw); err != nil {
		t.Fatal(err)
	}
	for _, key := range []string{"version", "revision", "time", "component"} {
		if _, ok := raw[key]; !ok {
			t.Fatalf("missing camelCase key %q in %s", key, or.Body.String())
		}
	}
}

func TestCapabilitiesAndBaselineScopes(t *testing.T) {
	t.Parallel()
	s := systemServer(t)
	h := s.Handler()

	for _, path := range []string{"/api/v1/capabilities", "/api/v1/baseline"} {
		unauth := httptest.NewRequest(http.MethodGet, path, nil)
		ur := httptest.NewRecorder()
		h.ServeHTTP(ur, unauth)
		if ur.Code != http.StatusUnauthorized {
			t.Fatalf("%s unauth %d %s", path, ur.Code, ur.Body.String())
		}

		forbid := httptest.NewRequest(http.MethodGet, path, nil)
		forbid.Header.Set("Authorization", "Bearer "+auditOnlyToken)
		fr := httptest.NewRecorder()
		h.ServeHTTP(fr, forbid)
		if fr.Code != http.StatusForbidden {
			t.Fatalf("%s audit-only %d %s", path, fr.Code, fr.Body.String())
		}
	}

	creq := httptest.NewRequest(http.MethodGet, "/api/v1/capabilities", nil)
	creq.Header.Set("Authorization", "Bearer "+testToken)
	cr := httptest.NewRecorder()
	h.ServeHTTP(cr, creq)
	if cr.Code != http.StatusOK {
		t.Fatalf("caps %d %s", cr.Code, cr.Body.String())
	}
	if cr.Header().Get("Cache-Control") != "no-store" {
		t.Fatal("caps cache")
	}
	var caps generated.Capabilities
	dec := json.NewDecoder(strings.NewReader(cr.Body.String()))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&caps); err != nil {
		t.Fatalf("caps openapi: %v %s", err, cr.Body.String())
	}
	if caps.EngineVendor != "389 Project" || !caps.RequiredOK || len(caps.Controls) == 0 {
		t.Fatalf("%+v", caps)
	}

	breq := httptest.NewRequest(http.MethodGet, "/api/v1/baseline", nil)
	breq.Header.Set("Authorization", "Bearer "+testToken)
	br := httptest.NewRecorder()
	h.ServeHTTP(br, breq)
	if br.Code != http.StatusOK {
		t.Fatalf("baseline %d %s", br.Code, br.Body.String())
	}
	if br.Header().Get("Cache-Control") != "no-store" {
		t.Fatal("baseline cache")
	}
	var base generated.Baseline
	dec = json.NewDecoder(strings.NewReader(br.Body.String()))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&base); err != nil {
		t.Fatalf("baseline openapi: %v %s", err, br.Body.String())
	}
	if base.ExpectedRevision != "aaa" || base.AppliedRevision != "aaa" || base.ControlRevision != "bbb" || !base.Match {
		t.Fatalf("%+v", base)
	}
	if base.MarkerDN == nil || *base.MarkerDN == "" {
		t.Fatal("markerDN")
	}
}

func TestCapabilitiesUnavailableWithoutSystem(t *testing.T) {
	t.Parallel()
	s := testServer(t, nil)
	req := httptest.NewRequest(http.MethodGet, "/api/v1/capabilities", nil)
	req.Header.Set("Authorization", "Bearer "+testToken)
	rec := httptest.NewRecorder()
	s.Handler().ServeHTTP(rec, req)
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("status %d %s", rec.Code, rec.Body.String())
	}
	assertProblem(t, rec, "directory")
}

func TestSessionGetAndDeleteBodies(t *testing.T) {
	t.Parallel()
	s := systemServer(t)
	h := s.Handler()
	csrf, cookie := loginSession(t, h)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/session", nil)
	req.AddCookie(auth.NewSessionCookie(cookie, false, 0))
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("get %d %s", rec.Code, rec.Body.String())
	}
	if rec.Header().Get("Cache-Control") != "no-store" {
		t.Fatal("get cache")
	}
	var view generated.SessionView
	dec := json.NewDecoder(strings.NewReader(rec.Body.String()))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&view); err != nil {
		t.Fatalf("session openapi: %v %s", err, rec.Body.String())
	}
	if view.Id == "" || view.Kind != generated.Session || len(view.Scopes) == 0 {
		t.Fatalf("%+v", view)
	}
	if _, err := time.Parse(time.RFC3339, view.ExpiresAt.UTC().Format(time.RFC3339)); err != nil {
		t.Fatalf("expiresAt %v", view.ExpiresAt)
	}
	if strings.Contains(rec.Body.String(), testToken) || strings.Contains(rec.Body.String(), csrf) {
		t.Fatalf("secret in session view: %s", rec.Body.String())
	}

	bearerOnly := httptest.NewRequest(http.MethodGet, "/api/v1/session", nil)
	bearerOnly.Header.Set("Authorization", "Bearer "+testToken)
	br := httptest.NewRecorder()
	h.ServeHTTP(br, bearerOnly)
	if br.Code != http.StatusUnauthorized {
		t.Fatalf("bearer get session %d %s", br.Code, br.Body.String())
	}

	del := httptest.NewRequest(http.MethodDelete, "/api/v1/session", nil)
	del.Host = "127.0.0.1:8443"
	del.Header.Set("Origin", "http://127.0.0.1:8443")
	del.Header.Set(auth.CSRFHeader, csrf)
	del.AddCookie(auth.NewSessionCookie(cookie, false, 0))
	dr := httptest.NewRecorder()
	h.ServeHTTP(dr, del)
	if dr.Code != http.StatusNoContent {
		t.Fatalf("delete %d %s", dr.Code, dr.Body.String())
	}
	if dr.Body.Len() != 0 {
		t.Fatalf("delete body %q", dr.Body.String())
	}
	if dr.Header().Get("Cache-Control") != "no-store" {
		t.Fatal("delete cache")
	}
}

func assertProblem(t *testing.T, rec *httptest.ResponseRecorder, code string) {
	t.Helper()
	if rec.Header().Get(headerRequestID) == "" {
		t.Fatal("missing X-Request-ID")
	}
	var body generated.Problem
	dec := json.NewDecoder(strings.NewReader(rec.Body.String()))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&body); err != nil {
		t.Fatalf("problem openapi: %v %s", err, rec.Body.String())
	}
	if body.Type != problemTypePrefix+code {
		t.Fatalf("type %q want %s", body.Type, problemTypePrefix+code)
	}
	if body.Extensions == nil || body.Extensions.RequestId == nil || *body.Extensions.RequestId == "" {
		t.Fatalf("missing requestId in %s", rec.Body.String())
	}
}
