package api

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/hilather/go-lab-ldap-mcp/api/generated"
	"github.com/hilather/go-lab-ldap-mcp/internal/app"
	"github.com/hilather/go-lab-ldap-mcp/internal/auth"
	"github.com/hilather/go-lab-ldap-mcp/internal/observability"
)

func TestLivenessIgnoresLDAPOutageAndMismatch(t *testing.T) {
	t.Parallel()
	s := testServer(t, func() bool { return false })
	s.diagnostics = func() app.Diagnostics {
		return app.Diagnostics{Ready: false, MarkerMatch: false, Pool: app.PoolView{Max: 16}, Reset: app.ResetHint{State: "Ready"}}
	}
	h := s.Handler()
	live := httptest.NewRequest(http.MethodGet, "/health", nil)
	lr := httptest.NewRecorder()
	h.ServeHTTP(lr, live)
	if lr.Code != http.StatusOK || !strings.Contains(lr.Body.String(), `"live"`) {
		t.Fatalf("live %d %s", lr.Code, lr.Body.String())
	}
	ready := httptest.NewRequest(http.MethodGet, "/health/ready", nil)
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, ready)
	if rr.Code != http.StatusServiceUnavailable {
		t.Fatalf("ready %d %s", rr.Code, rr.Body.String())
	}
}

func TestDiagnosticsAuthenticatedNoSecrets(t *testing.T) {
	t.Parallel()
	s := testServer(t, func() bool { return true })
	s.diagnostics = func() app.Diagnostics {
		return app.Diagnostics{
			Ready: true, MarkerMatch: true,
			Pool:  app.PoolView{Active: 1, Idle: 3, Max: 16},
			Reset: app.ResetHint{State: "Ready"},
		}
	}
	h := s.Handler()

	unauth := httptest.NewRequest(http.MethodGet, "/api/v1/diagnostics", nil)
	ur := httptest.NewRecorder()
	h.ServeHTTP(ur, unauth)
	if ur.Code != http.StatusUnauthorized {
		t.Fatalf("unauth %d %s", ur.Code, ur.Body.String())
	}

	req := httptest.NewRequest(http.MethodGet, "/api/v1/diagnostics", nil)
	req.Header.Set("Authorization", "Bearer "+testToken)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("diag %d %s", rec.Code, rec.Body.String())
	}
	if rec.Header().Get("Cache-Control") != "no-store" {
		t.Fatal("cache")
	}
	var body generated.Diagnostics
	decodeOpenAPI(t, rec, &body)
	if !body.Ready || !body.MarkerMatch || body.Pool.Max != 16 || body.Reset.State != generated.ResetHintStateReady {
		t.Fatalf("%+v", body)
	}
	low := strings.ToLower(rec.Body.String())
	for _, n := range []string{"password", "secret", "/run/", "authorization", "token:"} {
		if strings.Contains(low, n) {
			t.Fatalf("secret-like %q in %s", n, rec.Body.String())
		}
	}
}

func TestMetricsPrometheusNoIdentityLabels(t *testing.T) {
	t.Parallel()
	reg := observability.NewRegistry(observability.BuildInfo{Version: "dev", Revision: "abc", Component: "labldap"})
	s := testServer(t, nil)
	s.metrics = reg
	s.metricsEnabled = true
	h := s.Handler()
	req := httptest.NewRequest(http.MethodGet, "/health", nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	mreq := httptest.NewRequest(http.MethodGet, "/metrics", nil)
	mrec := httptest.NewRecorder()
	h.ServeHTTP(mrec, mreq)
	if mrec.Code != http.StatusOK {
		t.Fatalf("metrics %d %s", mrec.Code, mrec.Body.String())
	}
	out := mrec.Body.String()
	if !strings.Contains(out, "labldap_build_info") || !strings.Contains(out, `route="/health"`) {
		t.Fatalf("%s", out)
	}
	if strings.Contains(out, testToken) || strings.Contains(out, "admin") && strings.Contains(out, "token") {
		t.Fatalf("identity: %s", out)
	}
}

func TestRevisionMismatchReadyFunc(t *testing.T) {
	t.Parallel()
	reg, err := auth.NewRegistry([]auth.Token{{
		ID: "admin", Scopes: []string{auth.ScopeDirectoryRead}, Secret: observability.Secret(testToken),
	}})
	if err != nil {
		t.Fatal(err)
	}
	s, err := New(Options{
		Registry: reg,
		Ready:    func() bool { return false },
		Diagnostics: func() app.Diagnostics {
			return app.Diagnostics{Ready: false, MarkerMatch: false, Reset: app.ResetHint{State: "Ready"}}
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest(http.MethodGet, "/health/ready", nil)
	rec := httptest.NewRecorder()
	s.Handler().ServeHTTP(rec, req)
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("%d %s", rec.Code, rec.Body.String())
	}
}
