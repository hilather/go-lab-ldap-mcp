//go:build integration

package dirsrv

import (
	"encoding/json"
	"path/filepath"
	"strings"
	"testing"

	"github.com/hilather/go-lab-ldap-mcp/internal/bootstrap"
	"github.com/hilather/go-lab-ldap-mcp/internal/directory/ds389"
)

func TestShippedMarkerLastAndCapabilities(t *testing.T) {
	inst := Start(t)
	_, guest := stageSeedApply(t, inst, seedYAML("merge"), seedCanary)
	out, err := execApply(t, inst, guest, nil)
	if err != nil {
		t.Fatalf("apply: %v\n%s", err, redactLogs(out, seedCanary, inst.password))
	}
	assertNoCanary(t, inst, out, seedCanary)

	var sum struct {
		OK           bool            `json:"ok"`
		Remaining    []string        `json:"remaining"`
		Capabilities json.RawMessage `json:"capabilities"`
		Drift        json.RawMessage `json:"drift"`
		Phases       []struct {
			Phase string `json:"phase"`
			OK    bool   `json:"ok"`
		} `json:"phases"`
	}
	if err := decodeSummary(out, &sum); err != nil {
		t.Fatalf("summary: %v\n%s", err, out)
	}
	if !sum.OK || len(sum.Remaining) != 0 {
		t.Fatalf("ok=%v remaining=%v", sum.OK, sum.Remaining)
	}
	if len(sum.Phases) == 0 || sum.Phases[len(sum.Phases)-1].Phase != "marker" || !sum.Phases[len(sum.Phases)-1].OK {
		t.Fatalf("marker not last: %+v", sum.Phases)
	}
	for i, p := range sum.Phases {
		if p.Phase == "marker" && i != len(sum.Phases)-1 {
			t.Fatal("marker ran before later phases")
		}
		if p.Phase == "capabilities" {
			t.Fatal("must not add phase.capabilities")
		}
	}

	var caps bootstrap.Capabilities
	if err := json.Unmarshal(sum.Capabilities, &caps); err != nil {
		t.Fatalf("capabilities: %v\n%s", err, sum.Capabilities)
	}
	if !caps.RequiredOK || (caps.EngineVendor == "" && caps.EngineVersion == "") || caps.AdapterVersion == "" {
		t.Fatalf("capabilities = %+v", caps)
	}
	if bytesContainSecret(sum.Capabilities, seedCanary, inst.password, "runtime-secret") {
		t.Fatal("capabilities leaked secret")
	}

	d := inst.Dial(t)
	marker := ldapSearch(t, d, "cn=labldap-baseline,dc=example,dc=test",
		"dn", "objectClass", "cn", "serialNumber", "owner", "description", "destinationIndicator")
	if !strings.Contains(marker, "cn=labldap-baseline,dc=example,dc=test") {
		t.Fatalf("missing marker:\n%s", marker)
	}
	if !strings.Contains(marker, "objectClass: device") {
		t.Fatalf("marker objectClass:\n%s", marker)
	}
	if strings.Contains(marker, seedCanary) || strings.Contains(marker, inst.password) || strings.Contains(strings.ToLower(marker), "password") {
		t.Fatalf("marker contained secret material:\n%s", redactLogs(marker, seedCanary, inst.password))
	}

	dir := t.TempDir()
	ca := filepath.Join(dir, "ca.crt")
	inst.WriteCA(t, ca)
	eng := ds389.Engine{}
	got, err := eng.ReadMarker(t.Context(), bootstrap.MarkerRequest{
		TreeRequest: bootstrap.TreeRequest{
			Suffix:     "dc=example,dc=test",
			DMPassword: inst.Password(),
			LDAPURL:    "ldaps://" + inst.LDAPSAddr,
			CAFile:     ca,
			Host:       inst.Hostname(t),
			UseLDAPS:   true,
		},
		DN: "cn=labldap-baseline,dc=example,dc=test",
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("marker encoding=%s revision=%s owner=%s", got.Encoding, got.AppliedRevision, got.ApplyVersion)
	if got.AppliedRevision == "" || got.AppliedRevision != got.ExpectedRevision {
		t.Fatalf("marker revisions = %+v", got)
	}
	if strings.Contains(got.AppliedRevision, seedCanary) || strings.Contains(got.ApplyVersion, seedCanary) {
		t.Fatal("marker revision is a secret digest")
	}

	prior := got.AppliedRevision
	eng.FailWriteMarker = bootstrap.PhaseError("marker", "apply_failed", "injected marker fail")
	err = eng.WriteMarker(t.Context(), bootstrap.MarkerRequest{
		TreeRequest: bootstrap.TreeRequest{
			Suffix:     "dc=example,dc=test",
			DMPassword: inst.Password(),
			LDAPURL:    "ldaps://" + inst.LDAPSAddr,
			CAFile:     ca,
			Host:       inst.Hostname(t),
			UseLDAPS:   true,
			Write:      true,
		},
		DN:               "cn=labldap-baseline,dc=example,dc=test",
		AppliedRevision:  "should-not-commit",
		ExpectedRevision: "should-not-commit",
		ApplyVersion:     "labldap-bootstrap/dev",
		AppliedAt:        "2026-08-13T00:00:00Z",
	})
	if err == nil {
		t.Fatal("expected injected marker failure")
	}
	after, err := ds389.Engine{}.ReadMarker(t.Context(), bootstrap.MarkerRequest{
		TreeRequest: bootstrap.TreeRequest{
			Suffix:     "dc=example,dc=test",
			DMPassword: inst.Password(),
			LDAPURL:    "ldaps://" + inst.LDAPSAddr,
			CAFile:     ca,
			Host:       inst.Hostname(t),
			UseLDAPS:   true,
		},
		DN: "cn=labldap-baseline,dc=example,dc=test",
	})
	if err != nil {
		t.Fatal(err)
	}
	if after.AppliedRevision != prior {
		t.Fatalf("partial write committed new marker: prior=%s after=%s", prior, after.AppliedRevision)
	}
}

func bytesContainSecret(b []byte, secrets ...string) bool {
	s := string(b)
	for _, sec := range secrets {
		if sec != "" && strings.Contains(s, sec) {
			return true
		}
	}
	return false
}
