//go:build integration

package dirsrv

import (
	"context"
	"errors"
	"os/exec"
	"strings"
	"testing"

	"github.com/hilather/go-lab-ldap-mcp/internal/apperr"
	"github.com/hilather/go-lab-ldap-mcp/internal/bootstrap"
	"github.com/hilather/go-lab-ldap-mcp/internal/directory/ds389"
)

func TestShippedApplyTLSAndCleartextReject(t *testing.T) {
	inst := Start(t)
	_, guest := stageApply(t, inst, "dc=example,dc=test")
	out, err := execApply(t, inst, guest, nil)
	if err != nil {
		t.Fatalf("apply: %v\n%s", err, out)
	}
	if !strings.Contains(out, `"phase": "tls"`) && !strings.Contains(out, `"phase":"tls"`) {
		t.Fatalf("missing phase.tls:\n%s", out)
	}
	if !strings.Contains(out, `"ok": true`) {
		t.Fatalf("apply not ok:\n%s", out)
	}

	bout, berr := exec.Command("docker", "exec", inst.Name, "ldapsearch", "-x",
		"-H", "ldap://127.0.0.1:3389",
		"-D", "cn=Directory Manager", "-y", guest.PW,
		"-s", "base", "-b", "", "namingContexts").CombinedOutput()
	if berr == nil {
		t.Fatalf("cleartext simple bind succeeded:\n%s", bout)
	}
	if !strings.Contains(string(bout), "Confidentiality required") && !strings.Contains(string(bout), "ldap_bind:") {
		t.Fatalf("unexpected cleartext bind error:\n%s", bout)
	}
}

func TestShippedApplyTLSWithoutLDAPURL(t *testing.T) {
	inst := Start(t)
	_, guest := stageApply(t, inst, "dc=example,dc=test")
	args := []string{
		"exec", inst.Name, guest.Bin, "apply",
		"--config", guest.Config,
		"--directory-manager-password-file", guest.PW,
		"--directory-ca-file", guest.CA,
		"--directory-host", inst.Hostname(t),
		"--dsconf-instance", "localhost",
	}
	out, err := exec.Command("docker", args...).CombinedOutput()
	if err != nil {
		t.Fatalf("apply without --ldap-url: %v\n%s", err, out)
	}
	if !strings.Contains(string(out), `"phase": "tls"`) && !strings.Contains(string(out), `"phase":"tls"`) {
		t.Fatalf("missing phase.tls:\n%s", out)
	}
	if !strings.Contains(string(out), `"ok": true`) {
		t.Fatalf("apply not ok:\n%s", out)
	}
}

func TestShippedValidateDetectsCleartext(t *testing.T) {
	inst := Start(t)
	_, guest := stageApply(t, inst, "dc=example,dc=test")
	createBackend(t, inst, "userroot", "dc=example,dc=test")
	out, err := execValidate(t, inst, guest)
	if err == nil {
		t.Fatalf("validate should fail while cleartext bind is enabled:\n%s", out)
	}
	if !strings.Contains(out, "phase.tls") || !strings.Contains(out, "cleartext_enabled") {
		t.Fatalf("want phase.tls cleartext_enabled:\n%s", out)
	}
}

func TestReconcileTLSMissingSASLLive(t *testing.T) {
	inst := Start(t)
	_, guest := stageApply(t, inst, "dc=example,dc=test")
	if out, err := execApply(t, inst, guest, nil); err != nil {
		t.Fatalf("apply: %v\n%s", err, out)
	}
	eng := ds389.Engine{Runner: ds389.Runner{Exec: dockerDSConf(inst.Name)}}
	_, err := eng.ReconcileTLS(t.Context(), bootstrap.TLSRequest{
		PasswordFile: guest.PW,
		Instance:     "localhost",
		LDAPURL:      "ldaps://" + inst.LDAPSAddr,
		LDAPAddr:     inst.LDAPAddr,
		CAFile:       writeHostCA(t, inst),
		Host:         inst.Hostname(t),
		UseLDAPS:     true,
		Password:     inst.Password(),
		RequiredSASL: []string{"OTP"},
		Write:        false,
	})
	if err == nil {
		t.Fatal("expected sasl_missing")
	}
	apperr.Assert(t, err).Code(apperr.CodeBootstrap).FieldPath("phase.tls")
	var e *apperr.Error
	if !errors.As(err, &e) || !hasFieldCode(e, "sasl_missing") {
		t.Fatalf("%v", err)
	}
}

func execValidate(t *testing.T, inst *Instance, g applyGuest) (string, error) {
	t.Helper()
	args := []string{
		"exec", inst.Name, g.Bin, "validate",
		"--config", g.Config,
		"--directory-manager-password-file", g.PW,
		"--ldap-url", "ldaps://127.0.0.1:3636",
		"--directory-ca-file", g.CA,
		"--directory-host", inst.Hostname(t),
		"--dsconf-instance", "localhost",
	}
	out, err := exec.Command("docker", args...).CombinedOutput()
	return string(out), err
}

func dockerDSConf(name string) ds389.ExecFunc {
	return func(ctx context.Context, bin string, args []string) (stdout, stderr []byte, err error) {
		cmd := exec.CommandContext(ctx, "docker", append([]string{"exec", name, bin}, args...)...)
		out, e := cmd.CombinedOutput()
		if e != nil {
			return out, nil, e
		}
		return out, nil, nil
	}
}

func writeHostCA(t *testing.T, inst *Instance) string {
	t.Helper()
	p := t.TempDir() + "/ca.crt"
	inst.WriteCA(t, p)
	return p
}

func hasFieldCode(e *apperr.Error, code string) bool {
	for _, f := range e.Fields() {
		if f.Code == code {
			return true
		}
	}
	return false
}
