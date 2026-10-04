//go:build integration

package dirsrv

import (
	"bytes"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/hilather/go-lab-ldap-mcp/internal/apperr"
	"github.com/hilather/go-lab-ldap-mcp/internal/config"
	"github.com/hilather/go-lab-ldap-mcp/internal/ldapserver"
	"github.com/hilather/go-lab-ldap-mcp/internal/ldapserver/store"
	"github.com/hilather/go-lab-ldap-mcp/internal/observability"
)

// TestTargetAttrUnknownNameRejected (contract C8; resolved CAND-33, oracle
// probes 16 and 17): a raw ACI whose targetattr names a type the pinned 389
// schema lacks is refused on both engines. 389 rejects the ACI add with
// invalidSyntax(21), so apply fails in phase.aci with server_reject; native
// fails at startup when ldapserver.New parses the ACI set (invalid_aci).
// The scenario compiles on both, because config validation does not parse
// raw ACI text.
func TestTargetAttrUnknownNameRejected(t *testing.T) {
	for _, ta := range []string{"fooBar", "pwdAccountLockedTime", "sn || person"} {
		t.Run(strings.ReplaceAll(ta, " ", ""), func(t *testing.T) {
			aci := `(target="ldap:///dc=example,dc=test")(targetattr="` + ta + `")(version 3.0; acl "labldap:schema-reject"; allow (read) userdn="ldap:///anyone";)`
			scenario := `apiVersion: labldap.dev/v1alpha1
kind: LabScenario
metadata: { name: schema-reject }
spec:
  directory: { suffix: "dc=example,dc=test", allowRawACI: true }
  transport: { ldaps: { enabled: true, port: 3636 } }
  runtimeAccount: { id: rt, passwordFile: secrets/runtime-ldap }
  acls:
    - id: schema-reject
      rawACI: '` + aci + `'
`
			if itEngine(t) == EngineNative {
				nativeStartupRejects(t, withITEngine(scenario), "does not exist in the 389 schema")
				return
			}
			inst := Start(t)
			hostDir, guest := stageApply(t, inst, "dc=example,dc=test")
			hostBad := filepath.Join(hostDir, "bad.yaml")
			if err := os.WriteFile(hostBad, []byte(withITEngine(scenario)), 0o600); err != nil {
				t.Fatal(err)
			}
			if out, err := exec.Command("docker", "cp", hostBad, inst.Name+":/tmp/labldap-apply/bad.yaml").CombinedOutput(); err != nil {
				t.Fatalf("cp bad.yaml: %v\n%s", err, out)
			}
			guest.Config = "/tmp/labldap-apply/bad.yaml"
			out, err := execApply(t, inst, guest, nil)
			if err == nil {
				t.Fatalf("expected server_reject:\n%s", out)
			}
			if !strings.Contains(out, "phase.aci") || !strings.Contains(out, "server_reject") || !strings.Contains(out, "labldap:schema-reject") {
				t.Fatalf("want phase.aci server_reject labldap:schema-reject:\n%s", out)
			}
		})
	}
}

// nativeStartupRejects compiles yaml and builds the native server the way
// startNative does, expecting ldapserver.New to fail with want.
func nativeStartupRejects(t *testing.T, yaml, want string) {
	t.Helper()
	dir := t.TempDir()
	sec := filepath.Join(dir, "secrets")
	if err := os.Mkdir(sec, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(sec, "runtime-ldap"), []byte("runtime-secret\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	cfgPath := filepath.Join(dir, "lab.yaml")
	compiled, err := config.Compile(t.Context(), []byte(yaml), cfgPath, config.LoadOptions{
		Caller:  config.CallerBootstrap,
		Secrets: config.DirSecretResolver(dir),
	})
	if err != nil {
		t.Fatalf("compile: %v", err)
	}
	var texts []string
	for _, a := range compiled.Data.ACIs {
		texts = append(texts, a.Text)
	}
	schema, err := ldapserver.StandardSchema()
	if err != nil {
		t.Fatal(err)
	}
	st, err := store.Open(filepath.Join(dir, "labldapd.bolt"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.Close() })
	srv, err := ldapserver.New(ldapserver.Options{
		Suffix:      compiled.Engine.Suffix,
		LDAPAddress: "127.0.0.1:0",
		Limits:      ldapserver.DefaultLimits(),
		Codec:       ldapserver.NewBERCodec(ldapserver.BERCodecOptions{}),
		Store:       st,
		Schema:      schema,
		ACITexts:    texts,
		Logger:      observability.NewLogger(&bytes.Buffer{}, observability.FormatJSON, observability.CurrentBuild("labldapd")),
	})
	if err == nil {
		_ = srv.Close()
		t.Fatal("native server started with an unknown targetattr name")
	}
	var ae *apperr.Error
	if !errors.As(err, &ae) {
		t.Fatalf("native startup error = %v, want an apperr with field aciTexts", err)
	}
	found := false
	for _, f := range ae.Fields() {
		if f.Code == "invalid_aci" && strings.Contains(f.Message, want) {
			found = true
		}
	}
	if !found {
		t.Fatalf("native startup fields = %#v, want invalid_aci mentioning %q", ae.Fields(), want)
	}
}
