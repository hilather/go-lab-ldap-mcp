package config_test

import (
	"strings"
	"testing"

	"github.com/hilather/go-lab-ldap-mcp/internal/apperr"
	"github.com/hilather/go-lab-ldap-mcp/internal/config"
)

func TestSettingsRequireSecureTransport(t *testing.T) {
	src := []byte(`
apiVersion: labldap.dev/v1alpha1
kind: LabScenario
metadata:
  name: x
spec:
  directory:
    suffix: dc=example,dc=test
  transport:
    insecureLabMode: false
    ldap: { enabled: true, port: 3389 }
    ldaps: { enabled: false, port: 3636 }
    startTLS: false
    allowCleartextBind: false
  runtimeAccount:
    id: rt
    passwordFile: /run/secrets/runtime-ldap
`)
	err := config.Validate(src, "insecure.yaml")
	if err == nil {
		t.Fatal("expected insecure transport to fail")
	}
	apperr.Assert(t, err).Code(apperr.CodeConfiguration)
}

func TestSettingsDefaultsSoftReset(t *testing.T) {
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
	p, err := config.Load(t.Context(), src, "def.yaml", config.LoadOptions{Caller: config.CallerControl})
	if err != nil {
		t.Fatal(err)
	}
	if p.Public.Spec.Lifecycle.SoftReset == nil || !*p.Public.Spec.Lifecycle.SoftReset {
		t.Fatal("softReset should default true")
	}
	if p.Public.Spec.Directory.PeopleRDN != "ou=people" {
		t.Fatalf("peopleRDN = %q", p.Public.Spec.Directory.PeopleRDN)
	}
	if p.Public.Spec.Management.Metrics.Enabled == nil || !*p.Public.Spec.Management.Metrics.Enabled {
		t.Fatal("metrics.enabled should default true")
	}
	if p.Public.Spec.Management.MCP.Enabled == nil || !*p.Public.Spec.Management.MCP.Enabled {
		t.Fatal("mcp.enabled should default true")
	}
}

func TestSettingsHonorMetricsDisabled(t *testing.T) {
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
  management:
    metrics:
      enabled: false
  runtimeAccount:
    id: rt
    passwordFile: /run/secrets/runtime-ldap
`)
	p, err := config.Load(t.Context(), src, "nometrics.yaml", config.LoadOptions{Caller: config.CallerControl})
	if err != nil {
		t.Fatal(err)
	}
	if p.Public.Spec.Management.Metrics.Enabled == nil || *p.Public.Spec.Management.Metrics.Enabled {
		t.Fatal("explicit metrics.enabled: false was overridden")
	}
}

func TestSettingsHonorMCPDisabled(t *testing.T) {
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
  management:
    mcp:
      enabled: false
  runtimeAccount:
    id: rt
    passwordFile: /run/secrets/runtime-ldap
`)
	p, err := config.Load(t.Context(), src, "nomcp.yaml", config.LoadOptions{Caller: config.CallerControl})
	if err != nil {
		t.Fatal(err)
	}
	if p.Public.Spec.Management.MCP.Enabled == nil || *p.Public.Spec.Management.MCP.Enabled {
		t.Fatal("explicit mcp.enabled: false was overridden")
	}
}

func TestAdditionalSuffixesValidation(t *testing.T) {
	base := `
apiVersion: labldap.dev/v1alpha1
kind: LabScenario
metadata:
  name: x
spec:
  directory:
    suffix: dc=example,dc=test
    additionalSuffixes: [%s]
  transport:
    ldaps: { enabled: true, port: 3636 }
  runtimeAccount:
    id: rt
    passwordFile: /run/secrets/runtime-ldap
`
	t.Run("sibling ok", func(t *testing.T) {
		src := []byte(strings.Replace(base, "[%s]", "[dc=region1,dc=example,dc=net]", 1))
		if err := config.Validate(src, "ok.yaml"); err != nil {
			t.Fatal(err)
		}
	})
	t.Run("equals primary", func(t *testing.T) {
		src := []byte(strings.Replace(base, "[%s]", "[dc=example,dc=test]", 1))
		err := config.Validate(src, "dup.yaml")
		if err == nil {
			t.Fatal("expected duplicate")
		}
		apperr.Assert(t, err).FieldCode("duplicate")
	})
	t.Run("nested", func(t *testing.T) {
		src := []byte(strings.Replace(base, "[%s]", "[ou=people,dc=example,dc=test]", 1))
		err := config.Validate(src, "nested.yaml")
		if err == nil {
			t.Fatal("expected nested")
		}
		apperr.Assert(t, err).FieldCode("nested_suffix")
	})
	t.Run("invalid", func(t *testing.T) {
		src := []byte(strings.Replace(base, "[%s]", "[not-a-dn]", 1))
		err := config.Validate(src, "bad.yaml")
		if err == nil {
			t.Fatal("expected invalid")
		}
		apperr.Assert(t, err).FieldCode("invalid_dn")
	})
}
