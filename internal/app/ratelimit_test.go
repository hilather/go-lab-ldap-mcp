package app

import (
	"testing"
	"time"

	"github.com/hilather/go-lab-ldap-mcp/internal/apperr"
)

func TestWindowLimitsByPrefix(t *testing.T) {
	t.Parallel()
	w := NewWindow(2, 1, 10, 1)
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	w.now = func() time.Time { return now }

	if err := w.Allow(t.Context(), "bind:actor:a"); err != nil {
		t.Fatal(err)
	}
	if err := w.Allow(t.Context(), "bind:actor:a"); err == nil || apperr.CodeOf(err) != apperr.CodeAuth {
		t.Fatalf("second bind: %v", err)
	}
	if err := w.Allow(t.Context(), "bind:ip:1"); err != nil {
		t.Fatal(err)
	}

	if err := w.Allow(t.Context(), "password:a"); err != nil {
		t.Fatal(err)
	}
	if err := w.Allow(t.Context(), "password:a"); err != nil {
		t.Fatal(err)
	}
	if err := w.Allow(t.Context(), "password:a"); err == nil {
		t.Fatal("third password must deny")
	}

	if !w.AllowKey("other") {
		t.Fatal("general budget")
	}
	now = now.Add(time.Minute)
	if err := w.Allow(t.Context(), "bind:actor:a"); err != nil {
		t.Fatal(err)
	}
}
