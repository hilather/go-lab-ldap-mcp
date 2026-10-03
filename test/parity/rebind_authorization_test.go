package parity

import (
	"strings"
	"testing"

	"github.com/hilather/go-lab-ldap-mcp/internal/config"
	"github.com/hilather/go-lab-ldap-mcp/test/fixtures/ldapwire"
)

func rebindAuthorizationOutcomes(t *testing.T, e engine) [][3]int64 {
	t.Helper()
	out := make([][3]int64, 0, 20)
	for i := 0; i < 20; i++ {
		codes, err := ldapwire.RebindAuthorization(t.Context(), e.addr(true), e.clientTLS(), userDN("alice"), userPasswords["alice"], e.dmSecret())
		if err != nil {
			t.Fatal(err)
		}
		if codes != [3]int64{50, 0, 6} {
			t.Fatalf("%s iteration=%d IDs1/2/3 codes=%v", e.name(), i, codes)
		}
		out = append(out, codes)
	}
	return out
}
func TestDialSummaryExcludesBindPassword(t *testing.T) {
	const secret = "bind-password-redaction-canary"
	got := dialSummary(userSpec(userDN("alice"), secret))
	if strings.Contains(got, secret) {
		t.Fatal("dial diagnostic contains bind password")
	}
	if !strings.Contains(got, userDN("alice")) {
		t.Fatal("dial diagnostic lacks bind DN")
	}
}

func anonymousEnabledRebindFixture(t *testing.T) *fixture {
	t.Helper()
	scenario := strings.Replace(string(scenarioYAML()), "allowAnonymousBind: false", "allowAnonymousBind: true", 1)
	secrets := config.MapResolver{"secrets/runtime": runtimePassword}
	for id, pw := range userPasswords {
		secrets["secrets/"+id] = pw
	}
	compiled, err := config.Compile(t.Context(), []byte(scenario), "rebind-anonymous.yaml", config.LoadOptions{Caller: config.CallerCLI, Secrets: secrets})
	if err != nil {
		t.Fatal(err)
	}
	return &fixture{compiled: compiled, tls: makeTLSFixture(t)}
}
func pipelinedAuthorizationOutcomes(t *testing.T, e engine) [][3]int64 {
	t.Helper()
	out := make([][3]int64, 0, 20)
	for i := 0; i < 20; i++ {
		codes, err := ldapwire.PipelinedAuthorization(t.Context(), e.addr(true), e.clientTLS(), userDN("alice"), userPasswords["alice"], e.dmSecret())
		if err != nil {
			t.Fatal(err)
		}
		if codes != [3]int64{50, 0, 6} {
			t.Fatalf("%s iteration=%d IDs1/2/3 codes=%v", e.name(), i, codes)
		}
		out = append(out, codes)
	}
	return out
}
