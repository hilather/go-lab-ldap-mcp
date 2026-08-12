package config_test

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/hilather/go-lab-ldap-mcp/internal/config"
	"github.com/hilather/go-lab-ldap-mcp/internal/config/v1alpha1"
)

func fixtureSecrets() config.MapResolver {
	return config.MapResolver{
		"secrets/runtime-ldap": "lab-fixture-runtime-password",
		"secrets/user-alice":   "lab-fixture-alice-password",
		"secrets/token-admin":  "lab-fixture-admin-token",
	}
}

func TestCompileExample(t *testing.T) {
	c, err := config.Compile(t.Context(), exampleYAML(t), "example-lab.yaml", config.LoadOptions{
		Caller:  config.CallerCLI,
		Secrets: fixtureSecrets(),
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(c.Normalized.Users) != 1 || c.Normalized.Users[0].ID != "alice" {
		t.Fatalf("users = %+v", c.Normalized.Users)
	}
	if len(c.Normalized.Groups) != 1 || c.Normalized.Groups[0].Members[0].ID != "alice" {
		t.Fatalf("groups = %+v", c.Normalized.Groups)
	}
	if c.Data.Creates[0].Kind != "container" || c.Data.Creates[len(c.Data.Creates)-1].Kind != "marker" {
		t.Fatalf("create order = %+v", c.Data.Creates)
	}
	if c.Data.Deletes[0].Kind != "marker" || c.Data.Deletes[len(c.Data.Deletes)-1].Kind != "container" {
		t.Fatalf("delete order = %+v", c.Data.Deletes)
	}
	if c.Data.ServiceAccount == "" || c.Data.Marker == "" {
		t.Fatal("runtime/marker missing")
	}
	if !strings.HasPrefix(c.Data.ACIs[0].ID, "labldap:runtime-") {
		t.Fatalf("runtime ACIs not first: %+v", c.Data.ACIs)
	}
	p1, err := c.RedactedJSON()
	if err != nil {
		t.Fatal(err)
	}
	c2, err := config.Compile(t.Context(), exampleYAML(t), "example-lab.yaml", config.LoadOptions{
		Caller:  config.CallerCLI,
		Secrets: fixtureSecrets(),
	})
	if err != nil {
		t.Fatal(err)
	}
	p2, err := c2.RedactedJSON()
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(p1, p2) {
		t.Fatal("repeated compile not byte-identical")
	}
	if c.Revisions.Directory != c2.Revisions.Directory || c.Revisions.Control != c2.Revisions.Control {
		t.Fatal("revisions drifted")
	}
	if bytes.Contains(p1, []byte("lab-fixture-alice-password")) || bytes.Contains(p1, []byte("lab-fixture-admin-token")) {
		t.Fatal("plan leaked secrets")
	}
}

func TestEmptyGroup(t *testing.T) {
	src := []byte(`
apiVersion: labldap.dev/v1alpha1
kind: LabScenario
metadata: { name: x }
spec:
  directory: { suffix: "dc=example,dc=test" }
  transport: { ldaps: { enabled: true, port: 3636 } }
  runtimeAccount: { id: rt, passwordFile: secrets/runtime-ldap }
  groups:
    - id: empty
      members: []
`)
	_, err := config.Compile(t.Context(), src, "empty.yaml", config.LoadOptions{Secrets: fixtureSecrets(), Caller: config.CallerCLI})
	if err == nil {
		t.Fatal("expected empty group to fail")
	}
	if !hasCode(mustFields(t, err), "empty_group") {
		t.Fatalf("fields = %#v", mustFields(t, err))
	}
}

func TestForbiddenUserAttrAndIdentity(t *testing.T) {
	src := []byte(`
apiVersion: labldap.dev/v1alpha1
kind: LabScenario
metadata: { name: x }
spec:
  directory: { suffix: "dc=example,dc=test" }
  transport: { ldaps: { enabled: true, port: 3636 } }
  runtimeAccount: { id: rt, passwordFile: secrets/runtime-ldap }
  users:
    - id: alice
      uid: bob
      dn: uid=alice,ou=people,dc=example,dc=test
      passwordFile: secrets/user-alice
      attributes:
        userPassword: nope
        memberOf: staff
`)
	_, err := config.Compile(t.Context(), src, "baduser.yaml", config.LoadOptions{Secrets: fixtureSecrets(), Caller: config.CallerCLI})
	if err == nil {
		t.Fatal("expected identity/attr errors")
	}
	fs := mustFields(t, err)
	if !hasCode(fs, "identity_mismatch") || !hasCode(fs, "forbidden_attribute") {
		t.Fatalf("fields = %#v", fs)
	}
}

func TestCycleAndMissingRef(t *testing.T) {
	src := []byte(`
apiVersion: labldap.dev/v1alpha1
kind: LabScenario
metadata: { name: x }
spec:
  directory: { suffix: "dc=example,dc=test", nestedGroups: true }
  transport: { ldaps: { enabled: true, port: 3636 } }
  runtimeAccount: { id: rt, passwordFile: secrets/runtime-ldap }
  users:
    - id: alice
      passwordFile: secrets/user-alice
  groups:
    - id: a
      members: [{ group: b }]
    - id: b
      members: [{ group: a }]
`)
	_, err := config.Compile(t.Context(), src, "cycle.yaml", config.LoadOptions{Secrets: fixtureSecrets(), Caller: config.CallerCLI})
	if err == nil {
		t.Fatal("expected cycle")
	}
	if !hasCode(mustFields(t, err), "cycle") {
		t.Fatalf("fields = %#v", mustFields(t, err))
	}
}

func TestPolicyLockoutAndScheme(t *testing.T) {
	src := []byte(`
apiVersion: labldap.dev/v1alpha1
kind: LabScenario
metadata: { name: x }
spec:
  directory: { suffix: "dc=example,dc=test" }
  transport: { ldaps: { enabled: true, port: 3636 } }
  runtimeAccount: { id: rt, passwordFile: secrets/runtime-ldap }
  passwordPolicy:
    maxAge: 24h
    warningAge: 48h
    lockout: { enabled: true, maxFailures: 0, lockoutDuration: 0s }
    storageScheme: rot13
`)
	_, err := config.Compile(t.Context(), src, "pol.yaml", config.LoadOptions{Secrets: fixtureSecrets(), Caller: config.CallerCLI})
	if err == nil {
		t.Fatal("expected policy errors")
	}
	fs := mustFields(t, err)
	if !hasCode(fs, "invalid_policy") || !hasCode(fs, "unsupported_scheme") {
		t.Fatalf("fields = %#v", fs)
	}
}

func TestACIInjectionAndCNConfig(t *testing.T) {
	src := []byte(`
apiVersion: labldap.dev/v1alpha1
kind: LabScenario
metadata: { name: x }
spec:
  directory: { suffix: "dc=example,dc=test" }
  transport: { ldaps: { enabled: true, port: 3636 } }
  runtimeAccount: { id: rt, passwordFile: secrets/runtime-ldap }
  users:
    - id: 'evil")('
      passwordFile: secrets/user-alice
  acls:
    - id: staff-read
      principal: { kind: user, ref: 'evil")(' }
      target: { kind: suffix }
      permissions: [read]
`)
	c, err := config.Compile(t.Context(), src, "inj.yaml", config.LoadOptions{Secrets: fixtureSecrets(), Caller: config.CallerCLI})
	if err != nil {
		t.Fatal(err)
	}
	for _, a := range c.Data.ACIs {
		if strings.Contains(a.Text, `evil")(`) {
			t.Fatalf("unescaped injection in ACI: %s", a.Text)
		}
		if strings.Contains(strings.ToLower(a.Text), "cn=config") {
			t.Fatalf("cn=config in ACI: %s", a.Text)
		}
	}
}

func TestWriteScopeDoesNotImplyOthers(t *testing.T) {
	src := []byte(`
apiVersion: labldap.dev/v1alpha1
kind: LabScenario
metadata: { name: x }
spec:
  directory: { suffix: "dc=example,dc=test" }
  transport: { ldaps: { enabled: true, port: 3636 } }
  runtimeAccount: { id: rt, passwordFile: secrets/runtime-ldap }
  tokens:
    - id: w
      secretFile: secrets/token-admin
      scopes: [directory:write]
`)
	c, err := config.Compile(t.Context(), src, "tok.yaml", config.LoadOptions{Secrets: fixtureSecrets(), Caller: config.CallerCLI})
	if err != nil {
		t.Fatal(err)
	}
	if len(c.Normalized.Tokens) != 1 {
		t.Fatal(c.Normalized.Tokens)
	}
	for _, s := range c.Normalized.Tokens[0].Scopes {
		if s == v1alpha1.ScopeDirectoryPassword || s == v1alpha1.ScopeLabReset || s == v1alpha1.ScopeLabExport {
			t.Fatalf("write implied %s", s)
		}
	}
}

func TestRevisionsSeedAndToken(t *testing.T) {
	base := exampleYAML(t)
	opt := func(alice, token string) config.LoadOptions {
		return config.LoadOptions{Caller: config.CallerCLI, Secrets: config.MapResolver{
			"secrets/runtime-ldap": "lab-fixture-runtime-password",
			"secrets/user-alice":   alice,
			"secrets/token-admin":  token,
		}}
	}
	a, err := config.Compile(t.Context(), base, "a.yaml", opt("alice-one", "token-one"))
	if err != nil {
		t.Fatal(err)
	}
	b, err := config.Compile(t.Context(), base, "b.yaml", opt("alice-two", "token-one"))
	if err != nil {
		t.Fatal(err)
	}
	if a.Revisions.Directory == b.Revisions.Directory {
		t.Fatal("seed password change should change directory revision when softReset is true")
	}
	c, err := config.Compile(t.Context(), base, "c.yaml", opt("alice-one", "token-two"))
	if err != nil {
		t.Fatal(err)
	}
	if a.Revisions.Directory != c.Revisions.Directory {
		t.Fatal("token change must not change directory revision")
	}
	if a.Revisions.Control == c.Revisions.Control {
		t.Fatal("token change should change control revision")
	}
}

func TestShuffledAttributesSameRevision(t *testing.T) {
	one := []byte(`
apiVersion: labldap.dev/v1alpha1
kind: LabScenario
metadata: { name: x }
spec:
  directory: { suffix: "dc=example,dc=test" }
  transport: { ldaps: { enabled: true, port: 3636 } }
  runtimeAccount: { id: rt, passwordFile: secrets/runtime-ldap }
  users:
    - id: alice
      passwordFile: secrets/user-alice
      attributes: { sn: A, givenName: B }
`)
	two := []byte(`
apiVersion: labldap.dev/v1alpha1
kind: LabScenario
metadata: { name: x }
spec:
  directory: { suffix: "dc=example,dc=test" }
  transport: { ldaps: { enabled: true, port: 3636 } }
  runtimeAccount: { id: rt, passwordFile: secrets/runtime-ldap }
  users:
    - id: alice
      passwordFile: secrets/user-alice
      attributes: { givenName: B, sn: A }
`)
	opt := config.LoadOptions{Caller: config.CallerCLI, Secrets: fixtureSecrets()}
	ca, err := config.Compile(t.Context(), one, "1.yaml", opt)
	if err != nil {
		t.Fatal(err)
	}
	cb, err := config.Compile(t.Context(), two, "2.yaml", opt)
	if err != nil {
		t.Fatal(err)
	}
	if ca.Revisions.Directory != cb.Revisions.Directory {
		t.Fatal("map order changed directory revision")
	}
}

func TestInvalidFixtureFiles(t *testing.T) {
	dir := filepath.Join("..", "..", "test", "fixtures", "config", "invalid")
	ents, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range ents {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".yaml") {
			continue
		}
		b, err := os.ReadFile(filepath.Join(dir, e.Name()))
		if err != nil {
			t.Fatal(err)
		}
		_, err = config.Compile(t.Context(), b, e.Name(), config.LoadOptions{
			Caller:  config.CallerCLI,
			Secrets: fixtureSecrets(),
		})
		if err == nil {
			t.Fatalf("%s: expected compile error", e.Name())
		}
	}
}
