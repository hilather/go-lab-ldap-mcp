package config_test

import (
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
