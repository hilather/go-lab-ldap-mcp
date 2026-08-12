package config_test

import (
	"testing"

	"github.com/hilather/go-lab-ldap-mcp/internal/config"
)

func TestParseAndEscapeDN(t *testing.T) {
	t.Parallel()
	got, err := config.ParseDN(`uid=foo\,bar,ou=people,dc=example,dc=test`)
	if err != nil {
		t.Fatal(err)
	}
	if got.String() != `uid=foo\,bar,ou=people,dc=example,dc=test` {
		t.Fatalf("canonical = %q", got.String())
	}
	rdn, err := config.BuildRDN("cn", "foo,bar")
	if err != nil {
		t.Fatal(err)
	}
	if rdn != `cn=foo\,bar` {
		t.Fatalf("rdn = %q", rdn)
	}
}

func TestDNCases(t *testing.T) {
	t.Parallel()
	cases := []struct {
		in   string
		ok   bool
		want string
	}{
		{`cn=José,dc=ex,dc=test`, true, `cn=José,dc=ex,dc=test`},
		{`cn=a\+b,dc=ex`, true, `cn=a\+b,dc=ex`},
		{`cn=a\=b,dc=ex`, true, `cn=a=b,dc=ex`},
		{`cn=\ leading,dc=ex`, true, `cn=\ leading,dc=ex`},
		{"cn=a\x00b,dc=ex", false, ""},
	}
	for _, tc := range cases {
		d, err := config.ParseDN(tc.in)
		if tc.ok && err != nil {
			t.Fatalf("%q: %v", tc.in, err)
		}
		if !tc.ok && err == nil {
			t.Fatalf("%q: expected error", tc.in)
		}
		if tc.ok && d.String() != tc.want {
			t.Fatalf("%q -> %q want %q", tc.in, d.String(), tc.want)
		}
	}
}

func TestDescendantIsStructural(t *testing.T) {
	t.Parallel()
	suffix, err := config.ParseDN("dc=test")
	if err != nil {
		t.Fatal(err)
	}
	child, err := config.ParseDN("dc=example,dc=test")
	if err != nil {
		t.Fatal(err)
	}
	contest, err := config.ParseDN("dc=contest")
	if err != nil {
		t.Fatal(err)
	}
	if !child.IsDescendantOf(suffix) {
		t.Fatal("example,test should be under test")
	}
	if contest.IsDescendantOf(suffix) {
		t.Fatal("dc=contest is not under dc=test")
	}
	if suffix.IsDescendantOf(suffix) {
		t.Fatal("equal is not a descendant")
	}
}
