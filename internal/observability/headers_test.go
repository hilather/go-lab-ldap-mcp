package observability_test

import (
	"net/http"
	"strings"
	"testing"

	"github.com/hilather/go-lab-ldap-mcp/internal/observability"
)

func TestSanitizeHeadersRedactsAuthAndCookies(t *testing.T) {
	t.Parallel()
	token := "lab-test-static-token-value-32ch"
	cookie := "labldap_session=opaque-session-cookie-value"
	h := http.Header{}
	h.Set("Authorization", "Bearer "+token)
	h.Set("Cookie", cookie)
	h.Set("X-CSRF-Token", "csrf-secret-value")
	h.Set("X-Request-ID", "req-1")
	got := observability.SanitizeHeaders(h)
	if got.Get("Authorization") != "[redacted]" || got.Get("Cookie") != "[redacted]" || got.Get("X-Csrf-Token") != "[redacted]" {
		t.Fatalf("%v", got)
	}
	if got.Get("X-Request-ID") != "req-1" {
		t.Fatalf("request id: %q", got.Get("X-Request-ID"))
	}
	if h.Get("Authorization") != "Bearer "+token {
		t.Fatal("original header mutated")
	}
	blob := got.Get("Authorization") + got.Get("Cookie") + got.Get("X-Csrf-Token")
	if strings.Contains(blob, token) || strings.Contains(blob, cookie) || strings.Contains(blob, "csrf-secret") {
		t.Fatalf("leaked: %s", blob)
	}
}
