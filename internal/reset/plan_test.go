package reset

import (
	"strings"
	"testing"

	"github.com/hilather/go-lab-ldap-mcp/internal/directory"
)

func testPlanCfg() PlanConfig {
	return PlanConfig{
		PeopleDN:         "ou=people,dc=example,dc=test",
		GroupsDN:         "ou=groups,dc=example,dc=test",
		Suffix:           "dc=example,dc=test",
		RuntimeDN:        "uid=rt,ou=people,dc=example,dc=test",
		MarkerDN:         "cn=labldap-baseline,dc=example,dc=test",
		ConfiguredUsers:  []string{"uid=alice,ou=people,dc=example,dc=test"},
		ConfiguredGroups: []string{"cn=staff,ou=groups,dc=example,dc=test"},
	}
}

func TestPlanNeverDeletesOutsideManagedOrPreserve(t *testing.T) {
	t.Parallel()
	cfg := testPlanCfg()
	inv := directory.ManagedInventory{
		Users: []string{
			"uid=alice,ou=people,dc=example,dc=test",
			"uid=rt,ou=people,dc=example,dc=test",
			"uid=runtime-extra,ou=people,dc=example,dc=test",
		},
		Groups: []string{
			"cn=staff,ou=groups,dc=example,dc=test",
			"cn=rogue,ou=groups,dc=example,dc=test",
		},
		Extra: []string{
			"cn=outside,dc=example,dc=test",
			"cn=config",
			"ou=people,dc=example,dc=test",
			"cn=labldap-baseline,dc=example,dc=test",
			"uid=nested,cn=child,ou=people,dc=example,dc=test",
		},
		Preserve: []string{"uid=rt,ou=people,dc=example,dc=test"},
	}
	p := BuildPlan(inv, cfg)
	for _, s := range p.Deletes {
		if strings.EqualFold(s.DN, cfg.RuntimeDN) || strings.EqualFold(s.DN, cfg.MarkerDN) ||
			strings.EqualFold(s.DN, cfg.PeopleDN) || strings.EqualFold(s.DN, cfg.GroupsDN) {
			t.Fatalf("preserve deleted: %+v", s)
		}
		if !strings.Contains(strings.ToLower(s.DN), "ou=people,") &&
			!strings.Contains(strings.ToLower(s.DN), "ou=groups,") {
			t.Fatalf("outside managed: %+v", s)
		}
		if strings.EqualFold(s.DN, "cn=outside,dc=example,dc=test") || strings.EqualFold(s.DN, "cn=config") {
			t.Fatalf("suffix/config leaked: %+v", s)
		}
	}
	var extra, runtime bool
	for _, s := range p.Deletes {
		if strings.Contains(s.DN, "runtime-extra") || strings.Contains(s.DN, "cn=rogue") || strings.Contains(s.DN, "uid=nested") {
			extra = true
		}
		if strings.Contains(s.DN, "uid=rt,") {
			runtime = true
		}
	}
	if !extra {
		t.Fatalf("direct LDAP extras missing: %+v", p.Deletes)
	}
	if runtime {
		t.Fatal("runtime account deleted")
	}
	if p.Counts.Extra < 2 {
		t.Fatalf("extra count %+v", p.Counts)
	}
}

func TestPlanDepthOrderGroupsBeforeUsers(t *testing.T) {
	t.Parallel()
	cfg := testPlanCfg()
	cfg.ConfiguredGroups = append(cfg.ConfiguredGroups, "cn=child,cn=staff,ou=groups,dc=example,dc=test")
	inv := directory.ManagedInventory{
		Users: []string{
			"uid=alice,ou=people,dc=example,dc=test",
			"uid=extra,ou=people,dc=example,dc=test",
		},
		Groups: []string{
			"cn=staff,ou=groups,dc=example,dc=test",
			"cn=child,cn=staff,ou=groups,dc=example,dc=test",
		},
	}
	p := BuildPlan(inv, cfg)
	if len(p.Deletes) < 4 {
		t.Fatalf("deletes %+v", p.Deletes)
	}
	var lastDepth = 1 << 20
	var sawChild, sawStaff bool
	for _, s := range p.Deletes {
		if s.Depth > lastDepth {
			t.Fatalf("not children-first: %+v", p.Deletes)
		}
		lastDepth = s.Depth
		if strings.HasPrefix(s.DN, "cn=child,") {
			sawChild = true
			if sawStaff {
				t.Fatal("parent group before nested child")
			}
		}
		if s.DN == "cn=staff,ou=groups,dc=example,dc=test" {
			sawStaff = true
		}
	}
	if !sawChild || !sawStaff {
		t.Fatalf("group order %+v", p.Deletes)
	}
}

func TestPlanDryRunDoesNotImplyMutation(t *testing.T) {
	t.Parallel()
	inv := directory.ManagedInventory{
		Users: []string{"uid=alice,ou=people,dc=example,dc=test"},
	}
	a := BuildPlan(inv, testPlanCfg())
	b := BuildPlan(inv, testPlanCfg())
	if a.Counts.Deleted != b.Counts.Deleted || len(a.Deletes) != 1 {
		t.Fatalf("plan not deterministic: %+v %+v", a, b)
	}
}
