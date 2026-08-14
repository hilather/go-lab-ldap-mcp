package ldapclient

import "testing"

func TestEscapeFilterAndDN(t *testing.T) {
	t.Parallel()
	if got := EscapeFilter("a*b(c)"); got == "a*b(c)" {
		t.Fatalf("filter not escaped: %q", got)
	}
	if got := EscapeDN("a+b,c"); got == "a+b,c" {
		t.Fatalf("dn not escaped: %q", got)
	}
	if EscapeFilter("alice") != "alice" {
		t.Fatal("safe filter value should pass through")
	}
}
