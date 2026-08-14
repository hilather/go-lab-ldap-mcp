package api

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/hilather/go-lab-ldap-mcp/internal/apperr"
	"github.com/hilather/go-lab-ldap-mcp/internal/directory"
)

func TestFormatAndSetETag(t *testing.T) {
	t.Parallel()
	rev := directory.Revision("abc123def")
	if got := FormatETag(rev); got != `"abc123def"` {
		t.Fatalf("etag = %q", got)
	}
	rec := httptest.NewRecorder()
	SetETag(rec, rev)
	if rec.Header().Get("ETag") != `"abc123def"` {
		t.Fatalf("header %q", rec.Header().Get("ETag"))
	}
	empty := httptest.NewRecorder()
	SetETag(empty, "")
	if empty.Header().Get("ETag") != "" {
		t.Fatal("empty revision must not set ETag")
	}
}

func TestParseIfMatch(t *testing.T) {
	t.Parallel()
	ok, err := ParseIfMatch(`"deadbeef"`)
	if err != nil || ok != "deadbeef" {
		t.Fatalf("ok: %q %v", ok, err)
	}

	_, err = ParseIfMatch("")
	if statusFor(err) != http.StatusPreconditionFailed {
		t.Fatalf("empty status %d %v", statusFor(err), err)
	}
	apperr.Assert(t, err).Code(apperr.CodeConfiguration).FieldPath("If-Match")

	req := httptest.NewRequest(http.MethodPatch, "/api/v1/users/alice", nil)
	_, err = RequireIfMatch(req)
	if statusFor(err) != http.StatusPreconditionFailed {
		t.Fatalf("missing header status %d", statusFor(err))
	}

	req.Header.Set("If-Match", `"cafe"`)
	got, err := RequireIfMatch(req)
	if err != nil || got != "cafe" {
		t.Fatalf("header: %q %v", got, err)
	}

	for _, bad := range []string{"deadbeef", `W/"deadbeef"`, "*", `"a", "b"`, `""`, `"ab\"c"`} {
		_, err := ParseIfMatch(bad)
		if err == nil || statusFor(err) != http.StatusBadRequest {
			t.Fatalf("%q: %v status %d", bad, err, statusFor(err))
		}
	}
}
