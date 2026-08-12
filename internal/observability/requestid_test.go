package observability_test

import (
	"context"
	"testing"

	"github.com/hilather/go-lab-ldap-mcp/internal/observability"
)

func TestRequestIDRoundTrip(t *testing.T) {
	t.Parallel()
	ctx := observability.WithRequestID(context.Background(), "req-from-http")
	if got := observability.RequestID(ctx); got != "req-from-http" {
		t.Fatalf("RequestID = %q", got)
	}
}

func TestNewRequestIDUnique(t *testing.T) {
	t.Parallel()
	a := observability.NewRequestID()
	b := observability.NewRequestID()
	if len(a) != 32 || len(b) != 32 {
		t.Fatalf("ids %q %q", a, b)
	}
	if a == b {
		t.Fatal("NewRequestID returned a collision")
	}
}

func TestWithRequestIDGeneratesWhenEmpty(t *testing.T) {
	t.Parallel()
	ctx := observability.WithRequestID(context.Background(), "")
	if observability.RequestID(ctx) == "" {
		t.Fatal("expected generated id")
	}
}

func TestRequestIDMissing(t *testing.T) {
	t.Parallel()
	if observability.RequestID(context.Background()) != "" {
		t.Fatal("empty context should have no id")
	}
	if observability.RequestID(nil) != "" {
		t.Fatal("nil context should have no id")
	}
}
