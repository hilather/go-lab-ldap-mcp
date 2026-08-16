//go:build integration

package dirsrv

import (
	"encoding/json"
	"path/filepath"
	"strings"
	"testing"

	"github.com/hilather/go-lab-ldap-mcp/internal/apperr"
	"github.com/hilather/go-lab-ldap-mcp/internal/bootstrap"
	"github.com/hilather/go-lab-ldap-mcp/internal/config"
	"github.com/hilather/go-lab-ldap-mcp/internal/directory/ds389"
	"github.com/hilather/go-lab-ldap-mcp/internal/observability"
)

const verifyCanary = "verify-canary-alice-12"

func TestShippedApplyVerifyRuntimeAndApp(t *testing.T) {
	inst := Start(t)
	_, guest := stageSeedApply(t, inst, seedYAML("merge"), verifyCanary)
	out, err := execApply(t, inst, guest, nil)
	if err != nil {
		t.Fatalf("apply: %v\n%s", err, redactLogs(out, verifyCanary, inst.password))
	}
	assertVerifyPhases(t, out)
	assertNoCanary(t, inst, out, verifyCanary)
	if strings.Contains(out, "runtime-secret") {
		t.Fatal("runtime password leaked")
	}

	d := inst.Dial(t)
	people := ldapSearch(t, d, "ou=people,dc=example,dc=test", "aci")
	if !strings.Contains(compactACI(people), `targetattr!="aci"`) {
		t.Fatalf("people-write must deny aci:\n%s", people)
	}
	for _, dn := range []string{
		"uid=labldap-probe-user,ou=people,dc=example,dc=test",
		"cn=labldap-probe-group,ou=groups,dc=example,dc=test",
		"cn=labldap-probe-marker,dc=example,dc=test",
		"uid=labldap-probe-lockout,ou=people,dc=example,dc=test",
		"uid=labldap-probe-disable,ou=people,dc=example,dc=test",
	} {
		got := ldapSearchAllowMissing(t, d, dn)
		if strings.Contains(got, dn) {
			t.Fatalf("probe left behind %s:\n%s", dn, got)
		}
	}

	var sum struct {
		OK        bool     `json:"ok"`
		Remaining []string `json:"remaining"`
		Phases    []struct {
			Phase  string         `json:"phase"`
			OK     bool           `json:"ok"`
			Counts map[string]int `json:"counts"`
		} `json:"phases"`
	}
	if err := decodeSummary(out, &sum); err != nil {
		t.Fatalf("summary: %v\n%s", err, out)
	}
	if !sum.OK {
		t.Fatalf("apply not ok:\n%s", out)
	}
	if len(sum.Remaining) != 0 {
		t.Fatalf("remaining = %v, want empty", sum.Remaining)
	}
	var appCounts map[string]int
	for _, p := range sum.Phases {
		if p.Phase == "verify_app" {
			appCounts = p.Counts
		}
	}
	if appCounts["skipped_lockout"] != 1 {
		t.Fatalf("expected skipped_lockout: %+v", appCounts)
	}

	before := ldapSearch(t, d, "uid=alice,ou=people,dc=example,dc=test", "modifyTimestamp", "sn")
	vout, err := execValidate(t, inst, guest)
	if err != nil {
		t.Fatalf("validate: %v\n%s", err, redactLogs(vout, verifyCanary, inst.password))
	}
	after := ldapSearch(t, d, "uid=alice,ou=people,dc=example,dc=test", "modifyTimestamp", "sn")
	if before != after {
		t.Fatalf("validate mutated alice\nbefore=%s\nafter=%s", before, after)
	}
	var vsum struct {
		Remaining []string `json:"remaining"`
		Phases    []struct {
			Phase string `json:"phase"`
		} `json:"phases"`
	}
	if err := decodeSummary(vout, &vsum); err != nil {
		t.Fatalf("validate summary: %v\n%s", err, vout)
	}
	for _, p := range vsum.Phases {
		if p.Phase == "verify_runtime" || p.Phase == "verify_app" {
			t.Fatalf("validate ran write probe %s", p.Phase)
		}
	}
	if len(vsum.Remaining) != 0 {
		t.Fatalf("validate remaining = %v, want empty", vsum.Remaining)
	}
}

func TestReconcileVerifyRuntimeEngine(t *testing.T) {
	inst := Start(t)
	_, guest := stageSeedApply(t, inst, seedYAML("merge"), verifyCanary)
	if out, err := execApply(t, inst, guest, nil); err != nil {
		t.Fatalf("apply: %v\n%s", err, redactLogs(out, verifyCanary, inst.password))
	}
	dir := t.TempDir()
	ca := filepath.Join(dir, "ca.crt")
	inst.WriteCA(t, ca)
	pw := config.ResolvedSecret{Value: observability.Secret(verifyCanary)}
	req := bootstrap.VerifyRequest{
		TreeRequest: bootstrap.TreeRequest{
			Suffix:          "dc=example,dc=test",
			PeopleDN:        "ou=people,dc=example,dc=test",
			GroupsDN:        "ou=groups,dc=example,dc=test",
			RuntimeDN:       "uid=rt,ou=people,dc=example,dc=test",
			RuntimePassword: observability.Secret("runtime-secret"),
			DMPassword:      inst.Password(),
			LDAPURL:         "ldaps://" + inst.LDAPSAddr,
			CAFile:          ca,
			Host:            inst.Hostname(t),
			Write:           true,
		},
		MarkerDN: "cn=labldap-baseline,dc=example,dc=test",
		Users: []config.NormalizedUser{{
			ID: "alice", UID: "alice", DN: "uid=alice,ou=people,dc=example,dc=test",
			Enabled: true, Password: &pw, ObjectClasses: config.RequiredUserObjectClasses(),
		}},
		Groups: []config.NormalizedGroup{{
			ID: "staff", DN: "cn=staff,ou=groups,dc=example,dc=test",
			Members: []config.MemberRef{{Kind: "user", ID: "alice", DN: "uid=alice,ou=people,dc=example,dc=test"}},
		}},
		Policy: config.NormalizedPolicy{LockoutEnabled: false},
	}
	res, err := ds389.Engine{}.VerifyRuntime(t.Context(), req)
	if err != nil {
		t.Fatal(err)
	}
	if res.Allowed == 0 || res.Denied == 0 {
		t.Fatalf("counts = %+v", res)
	}
	app, err := ds389.Engine{}.VerifyApp(t.Context(), req)
	if err != nil {
		t.Fatal(err)
	}
	if app.Binds != 1 || app.SkippedLockout != 1 || app.Groups != 1 {
		t.Fatalf("app = %+v", app)
	}
}

func TestShippedVerifyAppLockoutIsolated(t *testing.T) {
	inst := Start(t)
	yaml := strings.Replace(seedYAML("merge"),
		"lockout: { enabled: false, maxFailures: 0, lockoutDuration: 0s }",
		"lockout: { enabled: true, maxFailures: 2, lockoutDuration: 60s }",
		1)
	_, guest := stageSeedApply(t, inst, yaml, verifyCanary)
	out, err := execApply(t, inst, guest, nil)
	if err != nil {
		t.Fatalf("apply: %v\n%s", err, redactLogs(out, verifyCanary, inst.password))
	}
	assertVerifyPhases(t, out)
	assertNoCanary(t, inst, out, verifyCanary)
	var sum struct {
		OK     bool `json:"ok"`
		Phases []struct {
			Phase  string         `json:"phase"`
			Counts map[string]int `json:"counts"`
		} `json:"phases"`
	}
	if err := decodeSummary(out, &sum); err != nil {
		t.Fatalf("summary: %v\n%s", err, out)
	}
	if !sum.OK {
		t.Fatalf("lockout apply not ok:\n%s", out)
	}
	for _, p := range sum.Phases {
		if p.Phase == "verify_app" && p.Counts["skipped_lockout"] != 0 {
			t.Fatalf("lockout should run: %+v", p.Counts)
		}
	}
	d := inst.Dial(t)
	got := ldapSearchAllowMissing(t, d, "uid=labldap-probe-lockout,ou=people,dc=example,dc=test")
	if strings.Contains(got, "uid=labldap-probe-lockout") {
		t.Fatalf("lockout probe left behind:\n%s", got)
	}
	if err := userBind(t, d, "uid=alice,ou=people,dc=example,dc=test", verifyCanary); err != nil {
		t.Fatalf("alice locked by isolated lockout: %v", err)
	}
}

func TestVerifyRuntimeFailureIsNotOK(t *testing.T) {
	inst := Start(t)
	_, guest := stageApply(t, inst, "dc=example,dc=test")
	if out, err := execApply(t, inst, guest, nil); err != nil {
		t.Fatalf("tree apply: %v\n%s", err, out)
	}
	dir := t.TempDir()
	ca := filepath.Join(dir, "ca.crt")
	inst.WriteCA(t, ca)
	_, rerr := ds389.Engine{}.VerifyRuntime(t.Context(), bootstrap.VerifyRequest{
		TreeRequest: bootstrap.TreeRequest{
			Suffix:          "dc=example,dc=test",
			PeopleDN:        "ou=people,dc=example,dc=test",
			GroupsDN:        "ou=groups,dc=example,dc=test",
			RuntimeDN:       "uid=rt,ou=people,dc=example,dc=test",
			RuntimePassword: observability.Secret("wrong-runtime-password"),
			DMPassword:      inst.Password(),
			LDAPURL:         "ldaps://" + inst.LDAPSAddr,
			CAFile:          ca,
			Host:            inst.Hostname(t),
			Write:           true,
		},
	})
	if rerr == nil {
		t.Fatal("expected allow_failed")
	}
	apperr.Assert(t, rerr).Code(apperr.CodeBootstrap).FieldPath("phase.verify_runtime")
	if strings.Contains(rerr.Error(), "wrong-runtime-password") {
		t.Fatal("error leaked password")
	}
}

func assertVerifyPhases(t *testing.T, out string) {
	t.Helper()
	for _, phase := range []string{"verify_runtime", "verify_app"} {
		if !strings.Contains(out, `"phase": "`+phase+`"`) && !strings.Contains(out, `"phase":"`+phase+`"`) {
			t.Fatalf("missing %s phase:\n%s", phase, out)
		}
	}
	var raw map[string]any
	if err := decodeSummary(out, &raw); err != nil {
		t.Fatalf("summary: %v\n%s", err, out)
	}
	b, _ := json.Marshal(raw)
	if strings.Contains(string(b), verifyCanary) {
		t.Fatal("summary leaked canary")
	}
}
