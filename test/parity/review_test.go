package parity

import (
	"testing"

	ldap "github.com/go-ldap/ldap/v3"
	"github.com/hilather/go-lab-ldap-mcp/internal/config"
)

func reviewFixture(t *testing.T) *fixture {
	t.Helper()
	scenario := append(scenarioYAML(), []byte(`
    - id: review-filter
      rawACI: '(target="ldap:///ou=people,dc=example,dc=test")(targetattr="uid")(version 3.0; acl "labldap:review-filter"; allow (read,search) userdn="ldap:///uid=alice,ou=people,dc=example,dc=test";)'
`)...)
	secrets := config.MapResolver{"secrets/runtime": runtimePassword}
	for id, pw := range userPasswords {
		secrets["secrets/"+id] = pw
	}
	c, err := config.Compile(t.Context(), scenario, "review-parity.yaml", config.LoadOptions{Caller: config.CallerCLI, Secrets: secrets})
	if err != nil {
		t.Fatal(err)
	}
	return &fixture{compiled: c, tls: makeTLSFixture(t)}
}

func reviewSearchOutcomes(t *testing.T, e engine) []opOutcome {
	t.Helper()
	dm := e.dm(t)
	defer dm.Close()
	reader := mustDial(t, e, userSpec(userDN("alice"), userPasswords["alice"]))
	defer reader.Close()
	out := []opOutcome{searchOutcome(dm, suffixDN, ldap.ScopeWholeSubtree, 1, "(uid=alice)", []string{"uid"})}
	if out[0].Code != 0 || len(out[0].Entries) != 1 {
		t.Fatalf("exact size limit: %#v", out[0])
	}
	indexed := searchOutcome(dm, peopleDN, ldap.ScopeWholeSubtree, 0, "(&(uid=alice)(cn=Alice Anderson))", []string{"uid"})
	if indexed.Code != 0 || len(indexed.Entries) != 1 {
		t.Fatalf("indexed conjunction: %#v", indexed)
	}
	out = append(out, indexed)
	for _, filter := range []string{"(sn=Anderson)", "(!(sn=Anderson))", "(!(sn=Other))", "(sn=*)", "(&(uid=alice)(sn=Anderson))"} {
		step := searchOutcome(reader, userDN("alice"), ldap.ScopeBaseObject, 0, filter, []string{"uid"})
		if step.Code != 0 || len(step.Entries) != 0 {
			t.Fatalf("denied filter %s: %#v", filter, step)
		}
		out = append(out, step)
	}
	step := searchOutcome(reader, userDN("alice"), ldap.ScopeBaseObject, 0, "(|(uid=alice)(sn=Anderson))", []string{"uid"})
	if step.Code != 0 || len(step.Entries) != 1 {
		t.Fatalf("authorized OR: %#v", step)
	}
	return append(out, step)
}

func TestNativeReviewSearchParity(t *testing.T) {
	fx := reviewFixture(t)
	native := startNative(t, fx)
	defer native.close(t)
	reviewSearchOutcomes(t, native)
}
