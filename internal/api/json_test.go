package api

import (
	"strings"
	"testing"

	"github.com/hilather/go-lab-ldap-mcp/internal/apperr"
)

func TestDecodeJSONUnknownField(t *testing.T) {
	t.Parallel()
	var body sessionCreateBody
	err := DecodeJSON(strings.NewReader(`{"token":"x","extra":true}`), &body)
	if err == nil {
		t.Fatal("expected unknown field to fail")
	}
	apperr.Assert(t, err).Code(apperr.CodeConfiguration)
}

func TestDecodeJSONTrailing(t *testing.T) {
	t.Parallel()
	var body sessionCreateBody
	err := DecodeJSON(strings.NewReader(`{"token":"x"}{"y":1}`), &body)
	if err == nil {
		t.Fatal("expected trailing content to fail")
	}
	apperr.Assert(t, err).Code(apperr.CodeConfiguration)
}

func TestDecodeJSONOK(t *testing.T) {
	t.Parallel()
	var body sessionCreateBody
	if err := DecodeJSON(strings.NewReader(`{"token":"lab-example"}`), &body); err != nil {
		t.Fatal(err)
	}
	if body.Token != "lab-example" {
		t.Fatalf("token = %q", body.Token)
	}
}
