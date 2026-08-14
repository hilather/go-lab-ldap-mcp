package config

import (
	"errors"
	"testing"
	"time"

	"github.com/hilather/go-lab-ldap-mcp/internal/apperr"
)

func testCursorKey(t *testing.T) CursorKey {
	t.Helper()
	key := NewCursorKey()
	if len(key) != 32 {
		t.Fatalf("key len %d", len(key))
	}
	return key
}

func TestProtectCursorRoundTrip(t *testing.T) {
	t.Parallel()
	key := testCursorKey(t)
	in := Cursor{Query: "users|ali|2", Page: "abcd"}
	exp := time.Unix(1_800_000_000, 0)
	tok, err := ProtectCursor(key, in, exp)
	if err != nil {
		t.Fatal(err)
	}
	got, err := UnprotectCursor(key, tok, time.Unix(1_799_000_000, 0))
	if err != nil {
		t.Fatal(err)
	}
	if got != in {
		t.Fatalf("got %+v want %+v", got, in)
	}
}

func TestProtectCursorRejectsTamperExpiryAndOtherKey(t *testing.T) {
	t.Parallel()
	key := testCursorKey(t)
	tok, err := ProtectCursor(key, Cursor{Query: "q", Page: "p"}, time.Unix(2_000_000_000, 0))
	if err != nil {
		t.Fatal(err)
	}

	tampered := tok[:len(tok)-1] + "A"
	if _, err := UnprotectCursor(key, tampered, time.Unix(1_900_000_000, 0)); err == nil || !cursorInvalid(err) {
		t.Fatalf("tampered cursor: %v", err)
	}

	if _, err := UnprotectCursor(key, tok, time.Unix(2_000_000_000, 0)); err == nil || !cursorInvalid(err) {
		t.Fatalf("expired cursor: %v", err)
	}

	other := testCursorKey(t)
	if _, err := UnprotectCursor(other, tok, time.Unix(1_900_000_000, 0)); err == nil || !cursorInvalid(err) {
		t.Fatalf("foreign key: %v", err)
	}

	inner, err := EncodeCursor(Cursor{Query: "q", Page: "p"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := UnprotectCursor(key, inner, time.Unix(1_900_000_000, 0)); err == nil || !cursorInvalid(err) {
		t.Fatalf("unsigned inner codec: %v", err)
	}
}

func TestProtectCursorRequiresKeyAndExpiry(t *testing.T) {
	t.Parallel()
	if _, err := ProtectCursor(nil, Cursor{Query: "q"}, time.Unix(2, 0)); err == nil || !cursorInvalid(err) {
		t.Fatalf("empty key: %v", err)
	}
	key := testCursorKey(t)
	if _, err := ProtectCursor(key, Cursor{Query: "q"}, time.Time{}); err == nil || !cursorInvalid(err) {
		t.Fatalf("zero expiry: %v", err)
	}
}

func TestUnprotectCursorMalformed(t *testing.T) {
	t.Parallel()
	key := testCursorKey(t)
	for _, s := range []string{"", "%%%", "abc"} {
		if _, err := UnprotectCursor(key, s, time.Unix(1, 0)); err == nil || !cursorInvalid(err) {
			t.Fatalf("accepted %q: %v", s, err)
		}
	}
}

func TestEncodeCursorStillIndependent(t *testing.T) {
	t.Parallel()
	tok, err := EncodeCursor(Cursor{Query: "base|sub|(uid=a)|cn|50", Page: "01ab"})
	if err != nil {
		t.Fatal(err)
	}
	got, err := DecodeCursor(tok)
	if err != nil {
		t.Fatal(err)
	}
	if got.Query != "base|sub|(uid=a)|cn|50" || got.Page != "01ab" {
		t.Fatalf("%+v", got)
	}
	if _, err := DecodeCursor("not-a-cursor"); err == nil || !cursorInvalid(err) {
		t.Fatalf("malformed: %v", err)
	}
}

func cursorInvalid(err error) bool {
	var e *apperr.Error
	if !errors.As(err, &e) {
		return false
	}
	for _, f := range e.Fields() {
		if f.Path == "cursor" && f.Code == "invalid" {
			return true
		}
	}
	return false
}
