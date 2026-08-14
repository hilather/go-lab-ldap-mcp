package api

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"

	"github.com/hilather/go-lab-ldap-mcp/internal/apperr"
	"github.com/hilather/go-lab-ldap-mcp/internal/config"
)

func TestParsePageParams(t *testing.T) {
	t.Parallel()
	got, err := ParsePageParams(url.Values{}, 50, 500)
	if err != nil || got.PageSize != 50 || got.Cursor != "" {
		t.Fatalf("default %+v %v", got, err)
	}
	got, err = ParsePageParams(url.Values{"pageSize": {"10"}, "cursor": {"abc"}}, 50, 500)
	if err != nil || got.PageSize != 10 || got.Cursor != "abc" {
		t.Fatalf("explicit %+v %v", got, err)
	}
	_, err = ParsePageParams(url.Values{"pageSize": {"0"}}, 50, 500)
	if err == nil || statusFor(err) != http.StatusBadRequest {
		t.Fatalf("zero: %v", err)
	}
	apperr.Assert(t, err).Code(apperr.CodeConfiguration).FieldPath("pageSize")
	_, err = ParsePageParams(url.Values{"pageSize": {"nope"}}, 50, 500)
	if err == nil {
		t.Fatal("non-int")
	}
	_, err = ParsePageParams(url.Values{"pageSize": {"501"}}, 50, 500)
	if err == nil {
		t.Fatal("too large")
	}
	apperr.Assert(t, err).FieldPath("pageSize")
}

func TestServerParsePageParamsUsesConfiguredLimits(t *testing.T) {
	t.Parallel()
	s, err := New(Options{PageSizeDefault: 7, PageSizeMax: 9})
	if err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest(http.MethodGet, "/api/v1/users?pageSize=8", nil)
	got, err := s.parsePageParams(req)
	if err != nil || got.PageSize != 8 {
		t.Fatalf("%+v %v", got, err)
	}
	req = httptest.NewRequest(http.MethodGet, "/api/v1/users?pageSize=10", nil)
	_, err = s.parsePageParams(req)
	if err == nil {
		t.Fatal("expected too_large")
	}
}

func TestServerCursorKeyRoundTrip(t *testing.T) {
	t.Parallel()
	key := config.NewCursorKey()
	s, err := New(Options{CursorKey: key})
	if err != nil {
		t.Fatal(err)
	}
	now := time.Unix(1_700_000_000, 0)
	tok, err := EncodeCursor(s.cursorKey, config.Cursor{Query: "users|", Page: "n"}, now)
	if err != nil {
		t.Fatal(err)
	}
	got, err := DecodeCursor(s.cursorKey, tok, "users|", now)
	if err != nil || got.Page != "n" {
		t.Fatalf("%+v %v", got, err)
	}
}

func TestCursorHelpers(t *testing.T) {
	t.Parallel()
	key := config.NewCursorKey()
	now := time.Unix(1_700_000_000, 0)
	tok, err := EncodeCursor(key, config.Cursor{Query: "users|", Page: "p1"}, now)
	if err != nil {
		t.Fatal(err)
	}
	got, err := DecodeCursor(key, tok, "users|", now)
	if err != nil || got.Query != "users|" || got.Page != "p1" {
		t.Fatalf("%+v %v", got, err)
	}
	_, err = DecodeCursor(key, tok, "users|other", now)
	if err == nil || statusFor(err) != http.StatusBadRequest {
		t.Fatalf("mismatch: %v", err)
	}
	apperr.Assert(t, err).Code(apperr.CodeConfiguration).FieldPath("cursor")

	_, err = DecodeCursor(key, tok+"x", "users|", now)
	if err == nil {
		t.Fatal("tampered")
	}
	apperr.Assert(t, err).FieldPath("cursor")

	_, err = DecodeCursor(key, tok, "users|", now.Add(config.DefaultCursorTTL+time.Second))
	if err == nil {
		t.Fatal("expired")
	}

	empty, err := DecodeCursor(key, "", "users|", now)
	if err != nil || empty.Query != "" {
		t.Fatalf("empty: %+v %v", empty, err)
	}
}

func TestWriteListEnvelope(t *testing.T) {
	t.Parallel()
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/api/v1/users", nil)
	writeList(rec, req, []string{"a"}, "next-1")
	if rec.Code != http.StatusOK {
		t.Fatalf("status %d", rec.Code)
	}
	var body struct {
		Items      []string `json:"items"`
		NextCursor string   `json:"nextCursor"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	if len(body.Items) != 1 || body.Items[0] != "a" || body.NextCursor != "next-1" {
		t.Fatalf("%+v", body)
	}

	rec = httptest.NewRecorder()
	writeList(rec, req, nil, "")
	if !json.Valid(rec.Body.Bytes()) || rec.Body.String() == "" {
		t.Fatalf("nil items %s", rec.Body.String())
	}
	if got := rec.Body.String(); !containsItemsArray(got) {
		t.Fatalf("expected items array: %s", got)
	}
}

func containsItemsArray(s string) bool {
	return json.Valid([]byte(s)) && (func() bool {
		var raw map[string]any
		if err := json.Unmarshal([]byte(s), &raw); err != nil {
			return false
		}
		_, ok := raw["items"].([]any)
		_, hasCursor := raw["nextCursor"]
		return ok && !hasCursor
	})()
}
