//go:build integration

package dirsrv

import (
	"errors"
	"os/exec"
	"strings"
	"testing"

	"github.com/hilather/go-lab-ldap-mcp/internal/apperr"
	"github.com/hilather/go-lab-ldap-mcp/internal/bootstrap"
	"github.com/hilather/go-lab-ldap-mcp/internal/directory/ds389"
)

func TestShippedApplyPluginsReadback(t *testing.T) {
	inst := Start(t)
	_, guest := stageApply(t, inst, "dc=example,dc=test")
	out, err := execApply(t, inst, guest, nil)
	if err != nil {
		t.Fatalf("apply: %v\n%s", err, out)
	}
	if !strings.Contains(out, `"phase": "plugins"`) && !strings.Contains(out, `"phase":"plugins"`) {
		t.Fatalf("missing plugins phase:\n%s", out)
	}
	mo := pluginShow(t, inst, guest.PW, "MemberOf Plugin")
	for _, want := range []string{`"nsslapd-pluginenabled"`, `"on"`, `"memberofattr"`, `"memberOf"`, `"memberofgroupattr"`, `"member"`} {
		if !strings.Contains(mo, want) {
			t.Fatalf("MemberOf read-back missing %s:\n%s", want, mo)
		}
	}
	ri := pluginShow(t, inst, guest.PW, "referential integrity postoperation")
	for _, want := range []string{`"nsslapd-pluginenabled"`, `"on"`, `"referint-membership-attr"`, `"member"`} {
		if !strings.Contains(ri, want) {
			t.Fatalf("RI read-back missing %s:\n%s", want, ri)
		}
	}
	sch := schemaQuery(t, inst, guest.PW, "nsAccountLock")
	if !strings.Contains(sch, `"nsAccountLock"`) {
		t.Fatalf("nsAccountLock missing:\n%s", sch)
	}
}

func TestShippedPluginsMissing(t *testing.T) {
	_, err := ds389.Engine{}.ReconcilePlugins(t.Context(), bootstrap.PluginRequest{
		PasswordFile: "/unused",
		Instance:     "localhost",
		Suffix:       "dc=example,dc=test",
		Plugins:      []string{"not-a-plugin"},
		Write:        true,
	})
	if err == nil {
		t.Fatal("expected plugin_missing")
	}
	a := apperr.Assert(t, err).Code(apperr.CodeBootstrap).FieldPath("phase.plugins")
	_ = a
	var e *apperr.Error
	if !errors.As(err, &e) {
		t.Fatal(err)
	}
	found := false
	for _, f := range e.Fields() {
		if f.Path == "phase.plugins" && f.Code == "plugin_missing" {
			found = true
		}
	}
	if !found {
		t.Fatalf("want phase.plugins plugin_missing: %v", err)
	}
}

func TestShippedPluginsEngineBehavior(t *testing.T) {
	d := startEngine(t, treeYAML())
	addPluginProbe(t, d)
	mo := ldapSearch(t, d, "uid=alice,dc=example,dc=test", "memberOf")
	if !strings.Contains(mo, "cn=staff,dc=example,dc=test") {
		t.Fatalf("memberOf not updated:\n%s", mo)
	}
	ldapDelete(t, d, "uid=alice,dc=example,dc=test")
	grp := ldapSearch(t, d, "cn=staff,dc=example,dc=test", "member")
	if strings.Contains(grp, "uid=alice") {
		t.Fatalf("RI left alice in group:\n%s", grp)
	}
	if err := userBind(t, d, "uid=bob,dc=example,dc=test", "BobPass1234"); err != nil {
		t.Fatalf("bob should bind before lock: %v", err)
	}
	lockAccount(t, d, "uid=bob,dc=example,dc=test")
	if err := userBind(t, d, "uid=bob,dc=example,dc=test", "BobPass1234"); err == nil {
		t.Fatal("disabled account still bound")
	}
	still := ldapSearch(t, d, "uid=bob,dc=example,dc=test", "dn", "nsAccountLock")
	if !strings.Contains(still, "uid=bob,dc=example,dc=test") {
		t.Fatalf("disabled entry was deleted:\n%s", still)
	}
}

func TestShippedValidateDoesNotMutatePlugins(t *testing.T) {
	inst := Start(t)
	_, guest := stageApply(t, inst, "dc=example,dc=test")
	if out, err := execApply(t, inst, guest, nil); err != nil {
		t.Fatalf("apply: %v\n%s", err, out)
	}
	beforeMO := pluginShow(t, inst, guest.PW, "MemberOf Plugin")
	beforeRI := pluginShow(t, inst, guest.PW, "referential integrity postoperation")
	if out, err := execValidate(t, inst, guest); err != nil {
		t.Fatalf("validate: %v\n%s", err, out)
	}
	afterMO := pluginShow(t, inst, guest.PW, "MemberOf Plugin")
	afterRI := pluginShow(t, inst, guest.PW, "referential integrity postoperation")
	if beforeMO != afterMO || beforeRI != afterRI {
		t.Fatalf("validate mutated plugins\nmo before=%s after=%s\nri before=%s after=%s", beforeMO, afterMO, beforeRI, afterRI)
	}
}

func pluginShow(t *testing.T, inst *Instance, pwfile, selector string) string {
	t.Helper()
	out, err := exec.Command("docker", "exec", inst.Name,
		"dsconf", "-D", "cn=Directory Manager", "-y", pwfile, "-j",
		"localhost", "plugin", "show", selector).CombinedOutput()
	if err != nil {
		t.Fatalf("plugin show %s: %v\n%s", selector, err, out)
	}
	return string(out)
}

func schemaQuery(t *testing.T, inst *Instance, pwfile, name string) string {
	t.Helper()
	out, err := exec.Command("docker", "exec", inst.Name,
		"dsconf", "-D", "cn=Directory Manager", "-y", pwfile, "-j",
		"localhost", "schema", "attributetypes", "query", name).CombinedOutput()
	if err != nil {
		t.Fatalf("schema query %s: %v\n%s", name, err, out)
	}
	return string(out)
}
