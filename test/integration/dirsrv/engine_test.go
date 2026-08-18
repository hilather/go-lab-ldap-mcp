package dirsrv

import (
	"strings"
	"testing"
)

func TestWithITEngine(t *testing.T) {
	const flow = `apiVersion: labldap.dev/v1alpha1
kind: LabScenario
metadata: { name: seed }
spec:
  directory: { suffix: "dc=example,dc=test" }
  transport: { ldaps: { enabled: true, port: 3636 } }
`

	t.Run("default_389ds", func(t *testing.T) {
		t.Setenv(EngineEnvVar, "")
		got := withITEngine(flow)
		if !strings.Contains(got, `directory: { engine: 389ds, suffix: "dc=example,dc=test" }`) {
			t.Fatalf("unset %s: %s", EngineEnvVar, got)
		}
	})

	t.Run("explicit_389ds", func(t *testing.T) {
		t.Setenv(EngineEnvVar, Engine389DS)
		got := withITEngine(flow)
		if !strings.Contains(got, `directory: { engine: 389ds, suffix: "dc=example,dc=test" }`) {
			t.Fatalf("engine=389ds: %s", got)
		}
	})

	t.Run("native", func(t *testing.T) {
		t.Setenv(EngineEnvVar, EngineNative)
		got := withITEngine(flow)
		if !strings.Contains(got, `directory: { engine: native, suffix: "dc=example,dc=test" }`) {
			t.Fatalf("engine=native: %s", got)
		}
	})

	t.Run("already_set", func(t *testing.T) {
		t.Setenv(EngineEnvVar, Engine389DS)
		src := strings.Replace(flow, `directory: { suffix:`, `directory: { engine: native, suffix:`, 1)
		got := withITEngine(src)
		if got != src {
			t.Fatalf("rewrote explicit engine:\n%s", got)
		}
	})

	t.Run("extra_flow_keys", func(t *testing.T) {
		t.Setenv(EngineEnvVar, Engine389DS)
		src := `  directory: { suffix: "dc=example,dc=test", allowRawACI: true }`
		got := withITEngine(src)
		if !strings.Contains(got, `directory: { engine: 389ds, suffix: "dc=example,dc=test", allowRawACI: true }`) {
			t.Fatalf("allowRawACI: %s", got)
		}
	})
}
