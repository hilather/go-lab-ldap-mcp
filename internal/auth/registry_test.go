package auth

import (
	"crypto/sha256"
	"strings"
	"testing"

	"github.com/hilather/go-lab-ldap-mcp/internal/apperr"
	"github.com/hilather/go-lab-ldap-mcp/internal/observability"
)

func TestLookupValidTokenExposesIDAndScopesOnly(t *testing.T) {
	t.Parallel()
	reg := mustRegistry(t, Token{
		ID:     "admin",
		Scopes: []string{ScopeDirectoryRead, ScopeDirectoryWrite},
		Secret: observability.Secret("lab-test-admin-token-value-32chars"),
	})
	p, ok := reg.Lookup("lab-test-admin-token-value-32chars")
	if !ok {
		t.Fatal("expected match")
	}
	if p.Kind != KindToken || p.ID != "admin" {
		t.Fatalf("principal = %+v", p)
	}
	if !p.Scopes.Has(ScopeDirectoryRead) || !p.Scopes.Has(ScopeDirectoryWrite) {
		t.Fatalf("scopes = %v", p.Scopes)
	}
	if strings.Contains(p.ID, "lab-test-admin-token") {
		t.Fatal("secret leaked into id")
	}
}

func TestLookupRejectsUnknownAndEmpty(t *testing.T) {
	t.Parallel()
	reg := mustRegistry(t, Token{
		ID:     "admin",
		Scopes: []string{ScopeDirectoryRead},
		Secret: observability.Secret("lab-test-admin-token-value-32chars"),
	})
	if _, ok := reg.Lookup("wrong-token-value-not-the-secret!!"); ok {
		t.Fatal("unknown token matched")
	}
	if _, ok := reg.Lookup(""); ok {
		t.Fatal("empty token matched")
	}
	if _, ok := reg.Lookup("lab-test-admin-token-value-32charsx"); ok {
		t.Fatal("prefix+extra matched")
	}
}

func TestDuplicateTokenValueRejected(t *testing.T) {
	t.Parallel()
	secret := observability.Secret("same-secret-value-for-both-tokens!")
	_, err := NewRegistry([]Token{
		{ID: "a", Scopes: []string{ScopeDirectoryRead}, Secret: secret},
		{ID: "b", Scopes: []string{ScopeDirectoryWrite}, Secret: secret},
	})
	if err == nil {
		t.Fatal("expected duplicate value error")
	}
	apperr.Assert(t, err).Code(apperr.CodeConfiguration)
	if strings.Contains(err.Error(), "same-secret-value") {
		t.Fatal("secret leaked in error")
	}
	if !strings.Contains(err.Error(), "duplicate") && apperr.PublicMessageOf(err) == "" {
		t.Fatalf("err = %v", err)
	}
}

func TestDuplicateTokenIDRejected(t *testing.T) {
	t.Parallel()
	_, err := NewRegistry([]Token{
		{ID: "admin", Secret: observability.Secret("token-one-value-xxxxxxxxxxxxxxxx")},
		{ID: "admin", Secret: observability.Secret("token-two-value-yyyyyyyyyyyyyyyy")},
	})
	if err == nil {
		t.Fatal("expected duplicate id")
	}
	apperr.Assert(t, err).Code(apperr.CodeConfiguration)
}

func TestConstantTimeDigestMatcher(t *testing.T) {
	t.Parallel()
	a := DigestSecret([]byte("lab-test-token-aaaaaaaaaaaaaaaa"))
	b := DigestSecret([]byte("lab-test-token-aaaaaaaaaaaaaaaa"))
	c := DigestSecret([]byte("lab-test-token-bbbbbbbbbbbbbbbb"))
	if !EqualDigest(a, b) {
		t.Fatal("identical secrets must compare equal")
	}
	if EqualDigest(a, c) {
		t.Fatal("distinct secrets must not compare equal")
	}
	if len(a) != sha256.Size {
		t.Fatalf("digest size %d", len(a))
	}
}

func TestParseBearer(t *testing.T) {
	t.Parallel()
	secret, ok, mal := ParseBearer("")
	if ok || mal || secret != "" {
		t.Fatalf("missing: %q %v %v", secret, ok, mal)
	}
	secret, ok, mal = ParseBearer("Basic abc")
	if ok || !mal {
		t.Fatalf("wrong scheme: %v %v", ok, mal)
	}
	secret, ok, mal = ParseBearer("Bearer")
	if ok || !mal {
		t.Fatalf("no value: %v %v", ok, mal)
	}
	secret, ok, mal = ParseBearer("Bearer   ")
	if ok || !mal {
		t.Fatalf("blank: %v %v", ok, mal)
	}
	secret, ok, mal = ParseBearer("Bearer one two")
	if ok || !mal {
		t.Fatalf("spaces: %v %v", ok, mal)
	}
	secret, ok, mal = ParseBearer("Bearer lab-token")
	if !ok || mal || secret != "lab-token" {
		t.Fatalf("got %q %v %v", secret, ok, mal)
	}
	secret, ok, mal = ParseBearer("bearer lab-token")
	if !ok || secret != "lab-token" {
		t.Fatalf("case: %q %v", secret, ok)
	}
}

func TestLookupDoesNotReturnOtherToken(t *testing.T) {
	t.Parallel()
	reg := mustRegistry(t,
		Token{ID: "read", Scopes: []string{ScopeDirectoryRead}, Secret: observability.Secret("read-token-secret-value-aaaaaaa")},
		Token{ID: "write", Scopes: []string{ScopeDirectoryWrite}, Secret: observability.Secret("write-token-secret-value-bbbbbb")},
	)
	p, ok := reg.Lookup("write-token-secret-value-bbbbbb")
	if !ok || p.ID != "write" {
		t.Fatalf("%+v %v", p, ok)
	}
	if p.Scopes.Has(ScopeDirectoryRead) {
		t.Fatal("wrong scopes")
	}
}

func mustRegistry(t *testing.T, tokens ...Token) *Registry {
	t.Helper()
	r, err := NewRegistry(tokens)
	if err != nil {
		t.Fatal(err)
	}
	return r
}
