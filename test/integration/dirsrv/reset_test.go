//go:build integration

package dirsrv

import (
	"strings"
	"testing"
)

func TestRuntimeInventoryAndProtectedDelete(t *testing.T) {
	env := startRuntimeEnv(t)
	env.rt.SetInventoryPageSize(1)
	addExtraPerson(t, env.inst, "uid=runtime-extra,ou=people,dc=example,dc=test")

	inv, err := env.rt.Inventory(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	if !containsDN(inv.Users, "uid=runtime-extra,ou=people,dc=example,dc=test") &&
		!containsDN(inv.Extra, "uid=runtime-extra,ou=people,dc=example,dc=test") {
		t.Fatalf("direct LDAP extra missing: %+v", inv)
	}
	if containsDN(inv.Users, "uid=rt,ou=people,dc=example,dc=test") {
		t.Fatalf("runtime listed as deletable: %+v", inv)
	}
	if !containsDN(inv.Preserve, "uid=rt,ou=people,dc=example,dc=test") {
		t.Fatalf("runtime not preserved: %+v", inv)
	}

	if err := env.rt.DeleteManaged(t.Context(), "uid=rt,ou=people,dc=example,dc=test"); err == nil {
		t.Fatal("runtime delete")
	}
	if err := env.rt.DeleteManaged(t.Context(), "cn=labldap-baseline,dc=example,dc=test"); err == nil {
		t.Fatal("marker delete")
	}
	if err := env.rt.DeleteManaged(t.Context(), "cn=outside,dc=example,dc=test"); err == nil {
		t.Fatal("outside delete")
	}
	if err := env.rt.DeleteManaged(t.Context(), "uid=runtime-extra,ou=people,dc=example,dc=test"); err != nil {
		t.Fatal(err)
	}
	inv2, err := env.rt.Inventory(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	if containsDN(inv2.Users, "uid=runtime-extra,ou=people,dc=example,dc=test") ||
		containsDN(inv2.Extra, "uid=runtime-extra,ou=people,dc=example,dc=test") {
		t.Fatalf("extra remained: %+v", inv2)
	}
	rt := ldapSearch(t, env.inst, "uid=rt,ou=people,dc=example,dc=test", "dn")
	if !strings.Contains(rt, "uid=rt,ou=people,dc=example,dc=test") {
		t.Fatal("runtime missing after inventory delete")
	}
}

func containsDN(in []string, want string) bool {
	for _, s := range in {
		if strings.EqualFold(s, want) {
			return true
		}
	}
	return false
}
