package api

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"testing/fstest"
	"time"

	"github.com/hilather/go-lab-ldap-mcp/internal/web"
)

func TestSPAHashedCacheAndIndexFallback(t *testing.T) {
	t.Parallel()
	fsys := fstest.MapFS{
		"index.html": {Data: []byte("<!doctype html><title>LabLDAP</title>"), ModTime: time.Unix(1, 0)},
		"assets/index-AbCdEf12.js": {
			Data:    []byte("export{}\n"),
			ModTime: time.Unix(2, 0),
		},
	}
	s, err := New(Options{Assets: fsys, Ready: func() bool { return false }, MetricsEnabled: true})
	if err != nil {
		t.Fatal(err)
	}
	h := s.Handler()

	js := httptest.NewRecorder()
	h.ServeHTTP(js, httptest.NewRequest(http.MethodGet, "/assets/index-AbCdEf12.js", nil))
	if js.Code != http.StatusOK {
		t.Fatalf("hashed asset: %d %s", js.Code, js.Body.String())
	}
	if got := js.Header().Get("Cache-Control"); got != "public, max-age=31536000, immutable" {
		t.Fatalf("hashed Cache-Control = %q", got)
	}
	if js.Body.String() != "export{}\n" {
		t.Fatalf("hashed body = %q", js.Body.String())
	}

	index := httptest.NewRecorder()
	h.ServeHTTP(index, httptest.NewRequest(http.MethodGet, "/", nil))
	if index.Code != http.StatusOK {
		t.Fatalf("index: %d %s", index.Code, index.Body.String())
	}
	if got := index.Header().Get("Cache-Control"); got != "no-cache" {
		t.Fatalf("index Cache-Control = %q", got)
	}
	if !strings.Contains(index.Body.String(), "LabLDAP") {
		t.Fatalf("index body = %q", index.Body.String())
	}

	fallback := httptest.NewRecorder()
	h.ServeHTTP(fallback, httptest.NewRequest(http.MethodGet, "/users/alice", nil))
	if fallback.Code != http.StatusOK {
		t.Fatalf("spa fallback: %d %s", fallback.Code, fallback.Body.String())
	}
	if got := fallback.Header().Get("Cache-Control"); got != "no-cache" {
		t.Fatalf("fallback Cache-Control = %q", got)
	}
	if !strings.Contains(fallback.Body.String(), "LabLDAP") {
		t.Fatalf("fallback body = %q", fallback.Body.String())
	}

	api404 := httptest.NewRecorder()
	h.ServeHTTP(api404, httptest.NewRequest(http.MethodGet, "/api/v1/nope", nil))
	if api404.Code != http.StatusNotFound {
		t.Fatalf("api miss: %d %s", api404.Code, api404.Body.String())
	}

	live := httptest.NewRecorder()
	h.ServeHTTP(live, httptest.NewRequest(http.MethodGet, "/health", nil))
	if live.Code != http.StatusOK {
		t.Fatalf("health: %d %s", live.Code, live.Body.String())
	}
}

func TestDefaultAssetsServePlaceholder(t *testing.T) {
	t.Parallel()
	s, err := New(Options{Ready: func() bool { return false }})
	if err != nil {
		t.Fatal(err)
	}
	rec := httptest.NewRecorder()
	s.Handler().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("status %d %s", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), "LabLDAP") {
		t.Fatalf("body = %q", rec.Body.String())
	}
	if got := rec.Header().Get("Cache-Control"); got != "no-cache" {
		t.Fatalf("Cache-Control = %q", got)
	}
}

func TestReservedManagementPath(t *testing.T) {
	t.Parallel()
	for _, p := range []string{"/api/v1/users", "/health", "/health/ready", "/metrics", "/mcp"} {
		if !reservedManagementPath(p) {
			t.Errorf("%s should be reserved", p)
		}
	}
	for _, p := range []string{"/", "/login", "/users/alice", "/assets/index-AbCdEf12.js"} {
		if reservedManagementPath(p) {
			t.Errorf("%s should not be reserved", p)
		}
	}
}

func TestCacheControlMatchesWebHelper(t *testing.T) {
	t.Parallel()
	if web.CacheControl("assets/x-12345678.js") != "public, max-age=31536000, immutable" {
		t.Fatal("hashed policy drifted")
	}
}
