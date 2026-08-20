package api

import (
	"crypto/tls"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/hilather/go-lab-ldap-mcp/internal/auth"
	"github.com/hilather/go-lab-ldap-mcp/internal/observability"
)

const testToken = "lab-test-static-token-value-32ch"

func testServer(t *testing.T, ready func() bool) *Server {
	t.Helper()
	reg, err := auth.NewRegistry([]auth.Token{{
		ID:     "admin",
		Scopes: []string{auth.ScopeDirectoryRead, auth.ScopeDirectoryWrite},
		Secret: observability.Secret(testToken),
	}})
	if err != nil {
		t.Fatal(err)
	}
	s, err := New(Options{
		Registry:       reg,
		Sessions:       auth.NewStore(auth.DefaultSessionConfig()),
		Ready:          ready,
		MetricsEnabled: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func TestWildcardCredentialedCORSRejected(t *testing.T) {
	t.Parallel()
	_, err := New(Options{AllowedOrigins: []string{"*"}})
	if err == nil {
		t.Fatal("wildcard credentialed CORS must be impossible")
	}
}

func TestHostAllowListRejectsSpoof(t *testing.T) {
	t.Parallel()
	s := testServer(t, nil)
	s.allowedHosts = []string{"127.0.0.1:8443"}
	h := s.Handler()

	ok := httptest.NewRequest(http.MethodGet, "http://127.0.0.1:8443/health", nil)
	ok.Host = "127.0.0.1:8443"
	or := httptest.NewRecorder()
	h.ServeHTTP(or, ok)
	if or.Code != http.StatusOK {
		t.Fatalf("loopback host = %d %s", or.Code, or.Body.String())
	}

	bad := httptest.NewRequest(http.MethodGet, "http://evil.test/health", nil)
	bad.Host = "evil.test"
	br := httptest.NewRecorder()
	h.ServeHTTP(br, bad)
	if br.Code != http.StatusBadRequest {
		t.Fatalf("spoofed host = %d %s", br.Code, br.Body.String())
	}

	ip := httptest.NewRequest(http.MethodGet, "http://192.0.2.10:8443/health", nil)
	ip.Host = "192.0.2.10:8443"
	ir := httptest.NewRecorder()
	h.ServeHTTP(ir, ip)
	if ir.Code != http.StatusOK {
		t.Fatalf("literal IP host = %d %s", ir.Code, ir.Body.String())
	}
}

func TestOriginPolicyRejectsCrossSitePreflight(t *testing.T) {
	t.Parallel()
	s := testServer(t, nil)
	h := s.Handler()
	req := httptest.NewRequest(http.MethodOptions, "http://127.0.0.1:8443/api/v1/users", nil)
	req.Host = "127.0.0.1:8443"
	req.Header.Set("Origin", "https://evil.test")
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	if rr.Code != http.StatusForbidden {
		t.Fatalf("cross-origin preflight = %d", rr.Code)
	}
}

func TestLivenessDuringLDAPOutage(t *testing.T) {
	t.Parallel()
	s := testServer(t, func() bool { return false })
	h := s.Handler()

	live := httptest.NewRequest(http.MethodGet, "/health", nil)
	lr := httptest.NewRecorder()
	h.ServeHTTP(lr, live)
	if lr.Code != http.StatusOK {
		t.Fatalf("liveness = %d %s", lr.Code, lr.Body.String())
	}

	ready := httptest.NewRequest(http.MethodGet, "/health/ready", nil)
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, ready)
	if rr.Code != http.StatusServiceUnavailable {
		t.Fatalf("ready = %d %s", rr.Code, rr.Body.String())
	}
}

func TestBearerAuth(t *testing.T) {
	t.Parallel()
	s := testServer(t, nil)
	s.metricsAuth = true
	h := s.Handler()

	for _, tc := range []struct {
		name   string
		header string
	}{
		{name: "missing"},
		{name: "malformed", header: "Basic abc"},
		{name: "invalid", header: "Bearer not-the-token-value-xxxxxxx"},
	} {
		req := httptest.NewRequest(http.MethodGet, "/metrics", nil)
		if tc.header != "" {
			req.Header.Set("Authorization", tc.header)
		}
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		if rec.Code != http.StatusUnauthorized {
			t.Fatalf("%s: status %d %s", tc.name, rec.Code, rec.Body.String())
		}
		body := rec.Body.String()
		if strings.Contains(body, "admin") || strings.Contains(body, testToken) {
			t.Fatalf("%s leaked token identity: %s", tc.name, body)
		}
	}

	req := httptest.NewRequest(http.MethodGet, "/metrics", nil)
	req.Header.Set("Authorization", "Bearer "+testToken)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("valid bearer: %d %s", rec.Code, rec.Body.String())
	}
}

func TestSessionLoginRotateAndCookieFlags(t *testing.T) {
	t.Parallel()
	s := testServer(t, nil)
	h := s.Handler()

	login := func(cookie string) *httptest.ResponseRecorder {
		req := httptest.NewRequest(http.MethodPost, "/api/v1/session", strings.NewReader(`{"token":"`+testToken+`"}`))
		req.Header.Set("Content-Type", "application/json")
		if cookie != "" {
			req.AddCookie(auth.NewSessionCookie(cookie, false, 0))
		}
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		return rec
	}

	first := login("")
	if first.Code != http.StatusOK {
		t.Fatalf("login: %d %s", first.Code, first.Body.String())
	}
	if strings.Contains(first.Body.String(), testToken) {
		t.Fatalf("raw token in login response: %s", first.Body.String())
	}
	var created sessionCreatedBody
	if err := json.Unmarshal(first.Body.Bytes(), &created); err != nil {
		t.Fatal(err)
	}
	if created.CSRFToken == "" {
		t.Fatal("missing csrf")
	}
	c := cookieNamed(first.Result(), auth.CookieName)
	if c == nil {
		t.Fatal("missing session cookie")
	}
	if !c.HttpOnly || c.Path != "/" || c.SameSite != http.SameSiteStrictMode {
		t.Fatalf("cookie flags = %+v", c)
	}
	if c.Secure {
		t.Fatal("secure set without TLS")
	}

	second := login(c.Value)
	if second.Code != http.StatusOK {
		t.Fatalf("rotate: %d %s", second.Code, second.Body.String())
	}
	next := cookieNamed(second.Result(), auth.CookieName)
	if next == nil || next.Value == c.Value {
		t.Fatal("login did not rotate cookie")
	}
	if s.sessions.Count() != 1 {
		t.Fatalf("session count %d", s.sessions.Count())
	}
}

func TestSessionCookieSecureOnTLS(t *testing.T) {
	t.Parallel()
	s := testServer(t, nil)
	ts := httptest.NewTLSServer(s.Handler())
	t.Cleanup(ts.Close)
	client := ts.Client()
	req, err := http.NewRequest(http.MethodPost, ts.URL+"/api/v1/session", strings.NewReader(`{"token":"`+testToken+`"}`))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(resp.Body)
		t.Fatalf("status %d %s", resp.StatusCode, b)
	}
	c := cookieNamed(resp, auth.CookieName)
	if c == nil || !c.Secure || !c.HttpOnly || c.SameSite != http.SameSiteStrictMode {
		t.Fatalf("tls cookie = %+v", c)
	}
	_ = tls.VersionTLS13
}

func TestSessionCSRFNotBypassedByBadAuthorization(t *testing.T) {
	t.Parallel()
	s := testServer(t, nil)
	h := s.Handler()
	_, cookie := loginSession(t, h)

	req := httptest.NewRequest(http.MethodDelete, "/api/v1/session", nil)
	req.Host = "127.0.0.1:8443"
	req.AddCookie(auth.NewSessionCookie(cookie, false, 0))
	req.Header.Set("Authorization", "Bearer not-the-token")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("status %d %s", rec.Code, rec.Body.String())
	}
	if _, _, ok := s.sessions.Lookup(cookie); !ok {
		t.Fatal("session cleared without CSRF and Origin")
	}
}

func TestMetricsDisabledHonored(t *testing.T) {
	t.Parallel()
	reg, err := auth.NewRegistry([]auth.Token{{
		ID:     "admin",
		Scopes: []string{auth.ScopeDirectoryRead},
		Secret: observability.Secret(testToken),
	}})
	if err != nil {
		t.Fatal(err)
	}
	s, err := New(Options{Registry: reg, MetricsEnabled: false})
	if err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest(http.MethodGet, "/metrics", nil)
	rec := httptest.NewRecorder()
	s.Handler().ServeHTTP(rec, req)
	if rec.Code != http.StatusNotFound {
		t.Fatalf("disabled metrics = %d %s", rec.Code, rec.Body.String())
	}
}

func TestSessionCSRFAndOrigin(t *testing.T) {
	t.Parallel()
	s := testServer(t, nil)
	h := s.Handler()
	csrf, cookie := loginSession(t, h)

	del := func(origin, token string) *httptest.ResponseRecorder {
		req := httptest.NewRequest(http.MethodDelete, "/api/v1/session", nil)
		req.Host = "example.com"
		req.AddCookie(auth.NewSessionCookie(cookie, false, 0))
		if origin != "" {
			req.Header.Set("Origin", origin)
		}
		if token != "" {
			req.Header.Set(auth.CSRFHeader, token)
		}
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		return rec
	}

	if rec := del("", csrf); rec.Code != http.StatusForbidden {
		t.Fatalf("missing origin: %d %s", rec.Code, rec.Body.String())
	}
	if rec := del("https://evil.test", csrf); rec.Code != http.StatusForbidden {
		t.Fatalf("bad origin: %d %s", rec.Code, rec.Body.String())
	}
	if rec := del("http://example.com", "wrong"); rec.Code != http.StatusForbidden {
		t.Fatalf("bad csrf: %d %s", rec.Code, rec.Body.String())
	}
	if rec := del("http://example.com", csrf); rec.Code != http.StatusNoContent {
		t.Fatalf("logout: %d %s", rec.Code, rec.Body.String())
	}
	if _, _, ok := s.sessions.Lookup(cookie); ok {
		t.Fatal("session survived logout")
	}
}

func TestSameOriginDefaultCORS(t *testing.T) {
	t.Parallel()
	s := testServer(t, nil)
	h := s.Handler()
	req := httptest.NewRequest(http.MethodOptions, "/health", nil)
	req.Host = "127.0.0.1:8443"
	req.Header.Set("Origin", "https://evil.test")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("cross-origin preflight = %d", rec.Code)
	}
	if rec.Header().Get("Access-Control-Allow-Origin") == "*" {
		t.Fatal("wildcard CORS header")
	}

	ok := httptest.NewRequest(http.MethodGet, "/health", nil)
	ok.Host = "127.0.0.1:8443"
	ok.Header.Set("Origin", "http://127.0.0.1:8443")
	or := httptest.NewRecorder()
	h.ServeHTTP(or, ok)
	if or.Code != http.StatusOK {
		t.Fatalf("same origin GET = %d", or.Code)
	}
	if got := or.Header().Get("Access-Control-Allow-Origin"); got != "http://127.0.0.1:8443" {
		t.Fatalf("allow-origin = %q", got)
	}
	if or.Header().Get("Access-Control-Allow-Origin") == "*" {
		t.Fatal("wildcard")
	}
}

func TestLoginUnknownJSONField(t *testing.T) {
	t.Parallel()
	s := testServer(t, nil)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/session", strings.NewReader(`{"token":"`+testToken+`","id":"admin"}`))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	s.Handler().ServeHTTP(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status %d %s", rec.Code, rec.Body.String())
	}
}

func loginSession(t *testing.T, h http.Handler) (csrf, cookie string) {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, "/api/v1/session", strings.NewReader(`{"token":"`+testToken+`"}`))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("login %d %s", rec.Code, rec.Body.String())
	}
	var body sessionCreatedBody
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	c := cookieNamed(rec.Result(), auth.CookieName)
	if c == nil {
		t.Fatal("no cookie")
	}
	return body.CSRFToken, c.Value
}

func cookieNamed(resp *http.Response, name string) *http.Cookie {
	for _, c := range resp.Cookies() {
		if c.Name == name {
			return c
		}
	}
	return nil
}
