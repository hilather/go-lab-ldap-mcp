package apperr_test

import (
	"errors"
	"fmt"
	"testing"

	"github.com/hilather/go-lab-ldap-mcp/internal/apperr"
)

func TestIdentitySurvivesWrapping(t *testing.T) {
	t.Parallel()
	base := apperr.New(apperr.CodeAuth, "invalid token")
	wrapped := fmt.Errorf("bearer: %w", base)
	if !errors.Is(wrapped, base) {
		t.Fatal("errors.Is lost identity after wrap")
	}
	var got *apperr.Error
	if !errors.As(wrapped, &got) {
		t.Fatal("errors.As failed")
	}
	if got.Code() != apperr.CodeAuth {
		t.Fatalf("code = %s", got.Code())
	}
	if got.PublicMessage() != "invalid token" {
		t.Fatalf("public = %q", got.PublicMessage())
	}
}

func TestCodeProbe(t *testing.T) {
	t.Parallel()
	err := fmt.Errorf("cfg: %w", apperr.New(apperr.CodeConfiguration, "unknown field").WithField(apperr.Field{
		Path: "spec.baseDN", Code: "unknown_field", Message: "field is not allowed",
	}))
	if !errors.Is(err, apperr.New(apperr.CodeConfiguration, "")) {
		t.Fatal("category probe should match")
	}
	if errors.Is(err, apperr.New(apperr.CodeAuth, "")) {
		t.Fatal("wrong category matched")
	}
}

func TestIndependentAssertions(t *testing.T) {
	t.Parallel()
	cause := errors.New("ldap: connection reset")
	err := apperr.New(apperr.CodeDirectory, "directory unavailable").
		Retry().
		WithField(apperr.Field{Path: "bind", Code: "unavailable", Message: "server closed the connection"}).
		Wrap(cause)

	apperr.Assert(t, err).
		Code(apperr.CodeDirectory).
		Public("directory unavailable").
		Retryable(true).
		FieldPath("bind").
		Cause(cause)
}

func TestAllRequiredCodes(t *testing.T) {
	t.Parallel()
	want := map[apperr.Code]bool{
		apperr.CodeConfiguration: false,
		apperr.CodeAuth:          false,
		apperr.CodeDirectory:     false,
		apperr.CodeReset:         false,
		apperr.CodeExport:        false,
		apperr.CodeBootstrap:     false,
	}
	for _, c := range apperr.KnownCodes() {
		if _, ok := want[c]; !ok {
			t.Fatalf("unexpected code %s", c)
		}
		want[c] = true
	}
	for c, seen := range want {
		if !seen {
			t.Fatalf("missing required code %s", c)
		}
	}
}

func TestFieldsAreCopied(t *testing.T) {
	t.Parallel()
	err := apperr.New(apperr.CodeExport, "limit exceeded").WithField(apperr.Field{Path: "export.bytes", Code: "limit", Message: "too large"})
	fields := err.Fields()
	fields[0].Message = "mutated"
	if err.Fields()[0].Message != "too large" {
		t.Fatal("Fields() must copy")
	}
}
