package auth

import (
	"net/http"
	"testing"
	"time"

	"github.com/hilather/go-lab-ldap-mcp/internal/directory"
)

func TestSessionCreateAndLookup(t *testing.T) {
	t.Parallel()
	s := NewStore(DefaultSessionConfig())
	cookie, csrf, sess, err := s.Create("admin", directory.ScopeSet{ScopeDirectoryRead})
	if err != nil {
		t.Fatal(err)
	}
	if cookie == "" || csrf == "" || sess.ID == "" {
		t.Fatalf("empty material: cookie=%q csrf=%q id=%q", cookie, csrf, sess.ID)
	}
	if cookie == csrf || cookie == sess.ID || csrf == sess.ID {
		t.Fatal("cookie, csrf, and public id must differ")
	}
	got, gotCSRF, ok := s.Lookup(cookie)
	if !ok || got.ID != sess.ID || gotCSRF != csrf {
		t.Fatalf("lookup %+v %q %v", got, gotCSRF, ok)
	}
	if got.TokenID != "admin" || !got.Scopes.Has(ScopeDirectoryRead) {
		t.Fatalf("session %+v", got)
	}
}

func TestSessionRotateReplacesCookie(t *testing.T) {
	t.Parallel()
	s := NewStore(DefaultSessionConfig())
	old, _, _, err := s.Create("admin", directory.ScopeSet{ScopeDirectoryRead})
	if err != nil {
		t.Fatal(err)
	}
	next, csrf, sess, err := s.Rotate(old, "admin", directory.ScopeSet{ScopeDirectoryWrite})
	if err != nil {
		t.Fatal(err)
	}
	if _, _, ok := s.Lookup(old); ok {
		t.Fatal("old cookie still valid")
	}
	got, gotCSRF, ok := s.Lookup(next)
	if !ok || got.ID != sess.ID || gotCSRF != csrf {
		t.Fatal("new session missing")
	}
	if !got.Scopes.Has(ScopeDirectoryWrite) {
		t.Fatal("rotated scopes not applied")
	}
}

func TestSessionExpiry(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 8, 14, 12, 0, 0, 0, time.UTC)
	s := NewStore(SessionConfig{Idle: time.Minute, Absolute: 5 * time.Minute, Max: 8})
	s.SetClock(func() time.Time { return now })
	cookie, _, _, err := s.Create("admin", nil)
	if err != nil {
		t.Fatal(err)
	}
	now = now.Add(61 * time.Second)
	if _, _, ok := s.Lookup(cookie); ok {
		t.Fatal("idle expiry should invalidate")
	}

	s = NewStore(SessionConfig{Idle: time.Hour, Absolute: 2 * time.Minute, Max: 8})
	now = time.Date(2026, 8, 14, 12, 0, 0, 0, time.UTC)
	s.SetClock(func() time.Time { return now })
	cookie, _, _, err = s.Create("admin", nil)
	if err != nil {
		t.Fatal(err)
	}
	now = now.Add(2*time.Minute + time.Second)
	if _, _, ok := s.Lookup(cookie); ok {
		t.Fatal("absolute expiry should invalidate")
	}
}

func TestSessionLogout(t *testing.T) {
	t.Parallel()
	s := NewStore(DefaultSessionConfig())
	cookie, _, _, err := s.Create("admin", nil)
	if err != nil {
		t.Fatal(err)
	}
	s.Delete(cookie)
	if _, _, ok := s.Lookup(cookie); ok {
		t.Fatal("deleted session still valid")
	}
}

func TestSessionMaxEvictsOldest(t *testing.T) {
	t.Parallel()
	s := NewStore(SessionConfig{Idle: time.Hour, Absolute: time.Hour, Max: 2})
	a, _, _, err := s.Create("a", nil)
	if err != nil {
		t.Fatal(err)
	}
	b, _, _, err := s.Create("b", nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, _, err := s.Create("c", nil); err != nil {
		t.Fatal(err)
	}
	if _, _, ok := s.Lookup(a); ok {
		t.Fatal("oldest session should be evicted")
	}
	if _, _, ok := s.Lookup(b); !ok {
		t.Fatal("newer session evicted")
	}
}

func TestCSRFCompare(t *testing.T) {
	t.Parallel()
	s := NewStore(DefaultSessionConfig())
	cookie, csrf, _, err := s.Create("admin", nil)
	if err != nil {
		t.Fatal(err)
	}
	if !s.ValidCSRF(cookie, csrf) {
		t.Fatal("matching csrf rejected")
	}
	if s.ValidCSRF(cookie, "wrong") {
		t.Fatal("wrong csrf accepted")
	}
	if s.ValidCSRF(cookie, "") {
		t.Fatal("empty csrf accepted")
	}
}

func TestSessionCookieFlags(t *testing.T) {
	t.Parallel()
	c := NewSessionCookie("abc", false, 0)
	if c.Name != CookieName || c.Path != "/" || !c.HttpOnly {
		t.Fatalf("cookie = %+v", c)
	}
	if c.SameSite != http.SameSiteStrictMode {
		t.Fatalf("samesite = %v", c.SameSite)
	}
	if c.Secure {
		t.Fatal("secure set on cleartext")
	}
	sec := NewSessionCookie("abc", true, 0)
	if !sec.Secure {
		t.Fatal("secure not set for TLS")
	}
	clear := ClearSessionCookie(true)
	if clear.MaxAge != -1 || !clear.Secure || !clear.HttpOnly {
		t.Fatalf("clear = %+v", clear)
	}
}

func TestOriginAllowedSameOrigin(t *testing.T) {
	t.Parallel()
	r, err := http.NewRequest(http.MethodPost, "http://127.0.0.1:8443/api/v1/session", nil)
	if err != nil {
		t.Fatal(err)
	}
	r.Host = "127.0.0.1:8443"
	if !OriginAllowed(r, "http://127.0.0.1:8443", nil) {
		t.Fatal("same origin rejected")
	}
	if OriginAllowed(r, "https://evil.test", nil) {
		t.Fatal("cross origin accepted")
	}
	if OriginAllowed(r, "", nil) {
		t.Fatal("empty origin accepted")
	}
	if !OriginAllowed(r, "https://ui.lab.test", []string{"https://ui.lab.test"}) {
		t.Fatal("allow-list rejected")
	}
}

func TestHostAllowedAndLoopback(t *testing.T) {
	t.Parallel()
	if !HostAllowed("evil.test", nil) {
		t.Fatal("empty allow-list must accept any Host")
	}
	if HostAllowed("evil.test:8443", []string{"127.0.0.1:8443"}) {
		t.Fatal("spoofed Host accepted")
	}
	if HostAllowed("", []string{"127.0.0.1:8443"}) {
		t.Fatal("empty Host accepted")
	}
	if !HostAllowed("127.0.0.1:8443", []string{"127.0.0.1:8443", "localhost:8443"}) {
		t.Fatal("loopback Host rejected")
	}
	got := LoopbackHosts("127.0.0.1:8443")
	if len(got) == 0 || !HostAllowed("localhost:8443", got) {
		t.Fatalf("loopback hosts = %v", got)
	}
	gotAll := LoopbackHosts("0.0.0.0:8443")
	if !HostAllowed("127.0.0.1:8443", gotAll) || HostAllowed("evil.test", gotAll) {
		t.Fatalf("bind-all listen must still allow-list loopback hosts, got %v", gotAll)
	}
}

func TestHostAllowedExtras(t *testing.T) {
	t.Parallel()
	defaults := LoopbackHosts("0.0.0.0:8443")
	hosts := append(append([]string{}, defaults...), LoopbackHostnames("0.0.0.0:8443")...)
	extras := append(append([]string{}, hosts...), "10.165.0.199", "lab.example.com", "localhost:9443")

	if !HostAllowed("control:8443", extras) {
		t.Fatal("control:listen-port must still match LoopbackHosts")
	}
	if !HostAllowed("10.165.0.199:9443", extras) {
		t.Fatal("host-only IP must match any port")
	}
	if !HostAllowed("localhost:9443", extras) {
		t.Fatal("host-only localhost (default extra) must match published port")
	}
	if !HostAllowed("LAB.EXAMPLE.COM:443", extras) {
		t.Fatal("host-only name match must be case-insensitive")
	}
	if HostAllowed("evil.test", extras) {
		t.Fatal("unlisted hostname must be rejected")
	}
	if HostAllowed("evil.test:8443", extras) {
		t.Fatal("spoofed Host must stay rejected when defaults+extras are set")
	}
	if HostAllowed("10.165.0.199:9443", defaults) {
		t.Fatal("public IP must not match LoopbackHosts alone")
	}
	if HostAllowed("*", extras) || hostEntryMatches("evil.test", "*") {
		t.Fatal("wildcard must never match")
	}
	if !HostAllowed("[::1]:9443", extras) {
		t.Fatal("IPv6 loopback host-only must match bracketed Request.Host")
	}
	if !HostAllowed("[2001:db8::1]:9443", []string{"[2001:db8::1]", "2001:db8::1"}) {
		t.Fatal("IPv6 host-only extra must match bracket form")
	}
	if !HostAllowed("[2001:db8::1]:9443", []string{"[2001:db8::1]:9443"}) {
		t.Fatal("IPv6 host:port extra must exact-match")
	}
	if HostAllowed("[2001:db8::1]:8443", []string{"[2001:db8::1]:9443"}) {
		t.Fatal("IPv6 host:port extra must not match a different port")
	}
}
