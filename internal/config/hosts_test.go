package config_test

import (
	"strings"
	"testing"

	"github.com/hilather/go-lab-ldap-mcp/internal/apperr"
	"github.com/hilather/go-lab-ldap-mcp/internal/config"
)

func allowedHostsScenario(hosts string) []byte {
	return []byte(`
apiVersion: labldap.dev/v1alpha1
kind: LabScenario
metadata:
  name: x
spec:
  directory:
    suffix: dc=example,dc=test
  transport:
    ldaps: { enabled: true, port: 3636 }
  management:
    listen: "0.0.0.0:8443"
    allowedHosts:` + hosts + `
  runtimeAccount:
    id: rt
    passwordFile: /run/secrets/runtime-ldap
`)
}

func TestAllowedHostsYAML(t *testing.T) {
	t.Setenv(config.AllowedHostsEnv, "")
	src := allowedHostsScenario(`
      - "10.165.0.199"
      - "lab.example.com"
      - "localhost:9443"
`)
	p, err := config.Load(t.Context(), src, "hosts.yaml", config.LoadOptions{Caller: config.CallerControl})
	if err != nil {
		t.Fatal(err)
	}
	got := p.Public.Spec.Management.AllowedHosts
	if len(got) != 3 || got[0] != "10.165.0.199" || got[1] != "lab.example.com" || got[2] != "localhost:9443" {
		t.Fatalf("allowedHosts = %#v", got)
	}
}

func TestAllowedHostsEnvAndCLIUnion(t *testing.T) {
	t.Setenv(config.AllowedHostsEnv, "10.165.0.199, lab.example.com")
	src := allowedHostsScenario(`
      - "localhost:9443"
`)
	p, err := config.Load(t.Context(), src, "hosts.yaml", config.LoadOptions{
		Caller:            config.CallerControl,
		ExtraAllowedHosts: []string{"control.lab.test", "10.165.0.199"},
	})
	if err != nil {
		t.Fatal(err)
	}
	got := strings.Join(p.Public.Spec.Management.AllowedHosts, ",")
	if got != "localhost:9443,10.165.0.199,lab.example.com,control.lab.test" {
		t.Fatalf("union = %q", got)
	}
}

func TestAllowedHostsRejected(t *testing.T) {
	t.Setenv(config.AllowedHostsEnv, "")
	cases := []struct {
		name  string
		hosts string
		code  string
	}{
		{"wildcard", "\n      - \"*\"\n", "wildcard"},
		{"empty", "\n      - \"\"\n", "empty"},
		{"scheme", "\n      - \"https://lab.example.com\"\n", "invalid_host"},
		{"path", "\n      - \"lab.example.com/admin\"\n", "invalid_host"},
		{"junk", "\n      - \"not a host\"\n", "invalid_host"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := config.Validate(allowedHostsScenario(tc.hosts), "bad.yaml")
			if err == nil {
				t.Fatal("expected error")
			}
			apperr.Assert(t, err).Code(apperr.CodeConfiguration)
			fields := mustFields(t, err)
			if !hasCode(fields, tc.code) {
				t.Fatalf("code %q missing in %#v", tc.code, fields)
			}
		})
	}
}

func TestAllowedHostsEnvWildcardRejected(t *testing.T) {
	t.Setenv(config.AllowedHostsEnv, "*")
	err := config.Validate(allowedHostsScenario(" []"), "env.yaml")
	if err == nil {
		t.Fatal("expected wildcard env to fail")
	}
	fields := mustFields(t, err)
	if !hasCode(fields, "wildcard") {
		t.Fatalf("fields = %#v", fields)
	}
}

func TestAllowedHostsCLIRejected(t *testing.T) {
	t.Setenv(config.AllowedHostsEnv, "")
	_, err := config.Load(t.Context(), allowedHostsScenario(" []"), "cli.yaml", config.LoadOptions{
		Caller:            config.CallerControl,
		ExtraAllowedHosts: []string{"https://evil.test"},
	})
	if err == nil {
		t.Fatal("expected CLI URL extra to fail")
	}
	apperr.Assert(t, err).Code(apperr.CodeConfiguration)
}

func TestAllowedHostsOmittedIsEmpty(t *testing.T) {
	t.Setenv(config.AllowedHostsEnv, "")
	src := []byte(`
apiVersion: labldap.dev/v1alpha1
kind: LabScenario
metadata:
  name: x
spec:
  directory:
    suffix: dc=example,dc=test
  transport:
    ldaps: { enabled: true, port: 3636 }
  runtimeAccount:
    id: rt
    passwordFile: /run/secrets/runtime-ldap
`)
	p, err := config.Load(t.Context(), src, "omit.yaml", config.LoadOptions{Caller: config.CallerControl})
	if err != nil {
		t.Fatal(err)
	}
	if len(p.Public.Spec.Management.AllowedHosts) != 0 {
		t.Fatalf("omitted allowedHosts = %#v", p.Public.Spec.Management.AllowedHosts)
	}
}

func TestSplitAndUnionAllowedHosts(t *testing.T) {
	if got := config.SplitHostList("  a, b ,c  "); strings.Join(got, "|") != "a|b|c" {
		t.Fatalf("split = %#v", got)
	}
	if config.SplitHostList("  ") != nil {
		t.Fatal("empty split")
	}
	got := config.UnionAllowedHosts([]string{"A", "b"}, []string{"a", "c"})
	if strings.Join(got, ",") != "A,b,c" {
		t.Fatalf("union = %#v", got)
	}
}

func TestAllowedHostsIPv6YAML(t *testing.T) {
	t.Setenv(config.AllowedHostsEnv, "")
	src := allowedHostsScenario(`
      - "[2001:db8::1]"
      - "[2001:db8::1]:9443"
      - "::1"
`)
	p, err := config.Load(t.Context(), src, "v6.yaml", config.LoadOptions{Caller: config.CallerControl})
	if err != nil {
		t.Fatal(err)
	}
	if len(p.Public.Spec.Management.AllowedHosts) != 3 {
		t.Fatalf("ipv6 hosts = %#v", p.Public.Spec.Management.AllowedHosts)
	}
}
