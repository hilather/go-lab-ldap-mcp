//go:build integration

package dirsrv

import (
	"strings"
	"testing"

	"github.com/hilather/go-lab-ldap-mcp/internal/app"
	"github.com/hilather/go-lab-ldap-mcp/internal/config"
	"github.com/hilather/go-lab-ldap-mcp/internal/directory"
	"github.com/hilather/go-lab-ldap-mcp/internal/observability"
	"github.com/hilather/go-lab-ldap-mcp/internal/reset"
)

func TestRuntimeInventoryAndProtectedDelete(t *testing.T) {
	env := startRuntimeEnv(t)
	env.rt.SetInventoryPageSize(1)
	addExtraPerson(t, env.dial, "uid=runtime-extra,ou=people,dc=example,dc=test")

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
	if err := env.rt.DeleteManaged(t.Context(), "uid=RT,ou=people,dc=example,dc=test"); err == nil {
		t.Fatal("runtime delete case fold")
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
	rt := ldapSearch(t, env.dial, "uid=rt,ou=people,dc=example,dc=test", "dn")
	if !strings.Contains(rt, "uid=rt,ou=people,dc=example,dc=test") {
		t.Fatal("runtime missing after inventory delete")
	}
}

func TestAppResetReappliesSeedAndLeavesMarker(t *testing.T) {
	env := startRuntimeEnv(t)
	before, err := env.rt.ReadMarker(t.Context())
	if err != nil || strings.TrimSpace(before.AppliedRevision) == "" {
		t.Fatalf("marker %+v %v", before, err)
	}
	addExtraPerson(t, env.dial, "uid=runtime-extra,ou=people,dc=example,dc=test")
	alicePW := "seed-alice-pass-12"
	sec := config.ResolvedSecret{Path: "alice.pw", Value: observability.Secret(alicePW)}
	gate := reset.NewGate()
	svc := app.New(app.Deps{
		Users:            env.rt.Users(),
		Groups:           env.rt.Groups(),
		Bind:             env.rt,
		Marker:           env.rt,
		ResetDir:         env.rt,
		Gate:             gate,
		ResetLock:        gate,
		SoftReset:        true,
		ScenarioName:     "lab",
		ExpectedRevision: before.AppliedRevision,
		PeopleDN:         "ou=people,dc=example,dc=test",
		GroupsDN:         "ou=groups,dc=example,dc=test",
		Suffix:           "dc=example,dc=test",
		RuntimeDN:        "uid=rt,ou=people,dc=example,dc=test",
		MarkerDN:         "cn=labldap-baseline,dc=example,dc=test",
		Secrets:          config.MapResolver{"alice.pw": alicePW},
		ResetUsers: []config.NormalizedUser{{
			ID: "alice", UID: "alice", DN: "uid=alice,ou=people,dc=example,dc=test",
			Enabled: true, Password: &sec,
			Attributes: []config.AttrKV{{Name: "sn", Value: "Seed"}},
		}},
		ResetGroups: []config.NormalizedGroup{{
			ID: "staff", DN: "cn=staff,ou=groups,dc=example,dc=test",
			Members: []config.MemberRef{{Kind: "user", ID: "alice", DN: "uid=alice,ou=people,dc=example,dc=test"}},
		}},
		BindTransport: directory.TransportLDAPS,
	})
	p := app.Principal{Kind: app.KindToken, ID: "admin", Scopes: directory.ScopeSet{
		"lab:reset", "directory:read", "directory:write",
	}}
	if _, err := svc.Reset.Start(t.Context(), p, app.ResetRequest{Name: "lab", ExpectedRevision: before.AppliedRevision}); err != nil {
		t.Fatal(err)
	}
	extra := ldapSearchAllowMissing(t, env.dial, "uid=runtime-extra,ou=people,dc=example,dc=test")
	if strings.Contains(extra, "uid=runtime-extra,ou=people,dc=example,dc=test") {
		t.Fatalf("extra remained:\n%s", extra)
	}
	if err := userBind(t, env.dial, "uid=alice,ou=people,dc=example,dc=test", alicePW); err != nil {
		t.Fatalf("alice bind after reset: %v", err)
	}
	after, err := env.rt.ReadMarker(t.Context())
	if err != nil || after.AppliedRevision != before.AppliedRevision {
		t.Fatalf("marker changed before=%q after=%q err=%v", before.AppliedRevision, after.AppliedRevision, err)
	}
	rt := ldapSearch(t, env.dial, "uid=rt,ou=people,dc=example,dc=test", "dn")
	if !strings.Contains(rt, "uid=rt,ou=people,dc=example,dc=test") {
		t.Fatal("runtime missing after reset")
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
