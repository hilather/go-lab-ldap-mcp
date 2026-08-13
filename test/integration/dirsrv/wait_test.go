//go:build integration

package dirsrv

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/hilather/go-lab-ldap-mcp/internal/apperr"
	"github.com/hilather/go-lab-ldap-mcp/internal/bootstrap"
	"github.com/hilather/go-lab-ldap-mcp/internal/directory/ds389"
)

func TestBootstrapWaitAndBind(t *testing.T) {
	inst := Start(t)
	dir := t.TempDir()
	caPath := filepath.Join(dir, "ca.crt")
	inst.WriteCA(t, caPath)
	pwPath := filepath.Join(dir, "dm.pw")
	if err := os.WriteFile(pwPath, []byte(inst.Password().Reveal()+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	sec := filepath.Join(dir, "secrets")
	if err := os.Mkdir(sec, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(sec, "runtime-ldap"), []byte("runtime-secret\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg := filepath.Join(dir, "lab.yaml")
	src := `apiVersion: labldap.dev/v1alpha1
kind: LabScenario
metadata: { name: wait }
spec:
  directory: { suffix: "dc=example,dc=test" }
  transport: { ldaps: { enabled: true, port: 3636 } }
  runtimeAccount: { id: rt, passwordFile: secrets/runtime-ldap }
`
	if err := os.WriteFile(cfg, []byte(src), 0o600); err != nil {
		t.Fatal(err)
	}

	sum, err := bootstrap.Run(t.Context(), bootstrap.Options{
		Command:       "apply",
		ConfigPath:    cfg,
		PasswordFile:  pwPath,
		LDAPURL:       "ldaps://" + inst.LDAPSAddr,
		CAFile:        caPath,
		DirectoryHost: inst.Hostname(t),
		Waiter:        ds389.Admin{},
		Backend:       stubBackend{},
		TLS:           stubTLS{},
		Policy:        stubPolicy{},
		Plugins:       stubPlugins{},
		Tree:          stubTree{},
	}, ioDiscard(), ioDiscard())
	if err != nil {
		t.Fatalf("apply wait: %v summary=%+v", err, sum)
	}
	if !sum.OK || len(sum.Phases) != 7 {
		t.Fatalf("%+v", sum)
	}

	_, err = bootstrap.Run(t.Context(), bootstrap.Options{
		Command:       "apply",
		ConfigPath:    cfg,
		PasswordFile:  writeFile(t, filepath.Join(dir, "wrong.pw"), "not-the-dm-password\n"),
		LDAPURL:       "ldaps://" + inst.LDAPSAddr,
		CAFile:        caPath,
		DirectoryHost: inst.Hostname(t),
		Waiter:        ds389.Admin{},
		Backend:       stubBackend{},
		TLS:           stubTLS{},
		Policy:        stubPolicy{},
		Plugins:       stubPlugins{},
		Tree:          stubTree{},
		Deadline:      2 * time.Second,
	}, ioDiscard(), ioDiscard())
	if err == nil {
		t.Fatal("wrong password must fail")
	}
	apperr.Assert(t, err).Code(apperr.CodeBootstrap).FieldPath("phase.wait")
	if got := waitCode(err); got != "bind" {
		t.Fatalf("wrong password code = %q, want bind", got)
	}

	wrongCA := generateTLS(t, "localhost")
	_, err = bootstrap.Run(t.Context(), bootstrap.Options{
		Command:       "apply",
		ConfigPath:    cfg,
		PasswordFile:  pwPath,
		LDAPURL:       "ldaps://" + inst.LDAPSAddr,
		CAFile:        filepath.Join(wrongCA.Dir, "ca", "ca.crt"),
		DirectoryHost: inst.Hostname(t),
		Waiter:        ds389.Admin{},
		Backend:       stubBackend{},
		TLS:           stubTLS{},
		Policy:        stubPolicy{},
		Plugins:       stubPlugins{},
		Tree:          stubTree{},
		Deadline:      3 * time.Second,
	}, ioDiscard(), ioDiscard())
	if err == nil {
		t.Fatal("wrong CA must fail")
	}
	apperr.Assert(t, err).Code(apperr.CodeBootstrap).FieldPath("phase.wait")
	if got := waitCode(err); got != "tls" {
		t.Fatalf("wrong CA code = %q, want tls", got)
	}
}

type stubBackend struct{}

func (stubBackend) Reconcile(context.Context, bootstrap.BackendRequest) (bootstrap.BackendResult, error) {
	return bootstrap.BackendResult{Action: "created", Name: "userroot", Suffix: "dc=example,dc=test"}, nil
}

type stubTLS struct{}

func (stubTLS) ReconcileTLS(context.Context, bootstrap.TLSRequest) (bootstrap.TLSResult, error) {
	return bootstrap.TLSResult{Transports: []string{"ldaps"}}, nil
}

type stubPolicy struct{}

func (stubPolicy) ReconcilePolicy(context.Context, bootstrap.PolicyRequest) (bootstrap.PolicyResult, error) {
	return bootstrap.PolicyResult{Applied: []string{"storageScheme"}}, nil
}

type stubPlugins struct{}

func (stubPlugins) ReconcilePlugins(context.Context, bootstrap.PluginRequest) (bootstrap.PluginResult, error) {
	return bootstrap.PluginResult{Applied: []string{"memberof"}}, nil
}

type stubTree struct{}

func (stubTree) ReconcileTree(context.Context, bootstrap.TreeRequest) (bootstrap.TreeResult, error) {
	return bootstrap.TreeResult{Matched: []string{"dc=example,dc=test"}}, nil
}

func waitCode(err error) string {
	var e *apperr.Error
	if !errors.As(err, &e) {
		return ""
	}
	for _, f := range e.Fields() {
		if f.Path == "phase.wait" {
			return f.Code
		}
	}
	return ""
}

func writeFile(t *testing.T, path, body string) string {
	t.Helper()
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func ioDiscard() *bytes.Buffer { return &bytes.Buffer{} }
