package reset

import (
	"strings"
	"testing"
)

func TestChecksumStableAndSecretFree(t *testing.T) {
	t.Parallel()
	a := Checksum([]ObjectSnap{
		{DN: "CN=staff,OU=groups,DC=example,DC=test", Kind: "group", Members: []string{"uid=bob,ou=people,dc=example,dc=test", "uid=alice,ou=people,dc=example,dc=test"}},
		{DN: "uid=alice,ou=people,dc=example,dc=test", Kind: "user"},
	})
	b := Checksum([]ObjectSnap{
		{DN: "uid=alice,ou=people,dc=example,dc=test", Kind: "user"},
		{DN: "cn=staff,ou=groups,dc=example,dc=test", Kind: "group", Members: []string{"uid=alice,ou=people,dc=example,dc=test", "uid=bob,ou=people,dc=example,dc=test"}},
	})
	if a == "" || a != b {
		t.Fatalf("checksum %s %s", a, b)
	}
	if strings.Contains(a, "alice") || strings.Contains(a, "password") {
		t.Fatal("checksum must be a digest")
	}
}

func TestCompareEqualityAndFailures(t *testing.T) {
	t.Parallel()
	sum := Checksum([]ObjectSnap{{DN: "uid=alice,ou=people,dc=example,dc=test", Kind: "user"}})
	ok := Compare("abc", "abc", sum, sum, 0, 0)
	if !ok.OK {
		t.Fatalf("%+v", ok)
	}
	if Compare("abc", "zzz", sum, sum, 0, 0).OK {
		t.Fatal("revision mismatch")
	}
	if Compare("abc", "abc", sum, sum, 1, 0).OK {
		t.Fatal("extras")
	}
	if Compare("abc", "abc", sum, sum, 0, 1).OK {
		t.Fatal("missing")
	}
	if Compare("abc", "abc", "fff", sum, 0, 0).OK {
		t.Fatal("checksum")
	}
	if Compare("abc", "", sum, sum, 0, 0).OK {
		t.Fatal("empty marker")
	}
}

func TestInjectorTripsOnce(t *testing.T) {
	t.Parallel()
	in := &Injector{}
	in.Set(PhaseDeleteUsers)
	if err := in.Trip(PhaseDeleteGroups); err != nil {
		t.Fatal(err)
	}
	if err := in.Trip(PhaseDeleteUsers); err == nil {
		t.Fatal("expected inject")
	}
	if err := in.Trip(PhaseDeleteUsers); err != nil {
		t.Fatal("second trip")
	}
}
