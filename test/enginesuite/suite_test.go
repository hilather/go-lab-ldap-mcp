package enginesuite

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// T-043 remap: TASKS acceptance + T-024 image contract. Cases are tagged
// observed (pinned 389 DS behavior) or proposed (stand-in until docs/03).
// Do not require docs/03-389ds-engine-adapter.md.
var t043Cases = []struct {
	name  string
	tag   string
	files []string
	tests []string
}{
	{name: "fresh apply", tag: "observed", files: []string{"test/integration/dirsrv/backend_test.go", "test/integration/dirsrv/seed_test.go"}, tests: []string{"TestShippedApplyBackendFreshAndMatch", "TestShippedApplySeedBindAndMembership"}},
	{name: "idempotent second apply", tag: "observed", files: []string{"test/integration/dirsrv/backend_test.go", "test/integration/dirsrv/seed_test.go"}, tests: []string{"TestShippedApplyBackendFreshAndMatch", "TestShippedApplySeedBindAndMembership"}},
	{name: "merge preserve", tag: "observed", files: []string{"test/integration/dirsrv/seed_test.go"}, tests: []string{"TestShippedApplySeedBindAndMembership"}},
	{name: "reset replace", tag: "observed", files: []string{"test/integration/dirsrv/seed_test.go", "test/integration/dirsrv/recover_test.go"}, tests: []string{"TestShippedApplySeedBindAndMembership", "TestResetRecoversPartialStates"}},
	{name: "backend name/suffix conflict", tag: "observed", files: []string{"test/integration/dirsrv/backend_test.go"}, tests: []string{"TestShippedApplyBackendConflict"}},
	{name: "TLS/require-secure-binds", tag: "observed", files: []string{"test/integration/dirsrv/tls_policy_test.go"}, tests: []string{"TestShippedApplyTLSAndCleartextReject"}},
	{name: "password policy read-back", tag: "observed", files: []string{"test/integration/dirsrv/pwpolicy_test.go"}, tests: []string{"TestShippedApplyPwpolicyReadback"}},
	{name: "MemberOf+RI+nsAccountLock", tag: "observed", files: []string{"test/integration/dirsrv/plugins_test.go"}, tests: []string{"TestShippedApplyPluginsReadback", "TestShippedPluginsEngineBehavior"}},
	{name: "ACI apply/read-back including runtime set", tag: "observed", files: []string{"test/integration/dirsrv/aci_test.go", "test/integration/dirsrv/verify_test.go"}, tests: []string{"TestShippedApplyACIReadback", "TestShippedApplyVerifyRuntimeAndApp"}},
	{name: "seed bind", tag: "observed", files: []string{"test/integration/dirsrv/seed_test.go"}, tests: []string{"TestShippedApplySeedBindAndMembership"}},
	{name: "runtime allow/deny", tag: "observed", files: []string{"test/integration/dirsrv/verify_test.go"}, tests: []string{"TestShippedApplyVerifyRuntimeAndApp"}},
	{name: "marker last", tag: "observed", files: []string{"test/integration/dirsrv/marker_test.go"}, tests: []string{"TestShippedMarkerLastAndCapabilities"}},
	{name: "secret-scan of test logs", tag: "observed", files: []string{"test/integration/dirsrv/redact.go", "test/integration/dirsrv/redact_test.go"}, tests: []string{"TestRedactLogs"}},
	{name: "T-024 image contract + digest pin", tag: "observed", files: []string{"deploy/docker/dirsrv-image-contract.md", "deploy/docker/dirsrv.digest", "test/integration/dirsrv/contract_test.go", "test/integration/dirsrv/harness_test.go"}, tests: []string{"TestImageRefIsDigest", "TestPinnedImageStartsAndIsHealthy"}},
	{name: "docs/03 extra dsconf adapter matrix", tag: "proposed", files: []string{"deploy/docker/dirsrv-image-contract.md"}, tests: nil},
}

func TestT043CaseInventory(t *testing.T) {
	root := repoRoot(t)
	if _, err := os.Stat(filepath.Join(root, "docs", "03-389ds-engine-adapter.md")); err == nil {
		t.Log("docs/03 is present; diff against this inventory and write an ADR if the suite must change")
	}
	for _, c := range t043Cases {
		t.Run(c.tag+"/"+c.name, func(t *testing.T) {
			if c.tag != "observed" && c.tag != "proposed" {
				t.Fatalf("tag %q", c.tag)
			}
			for _, rel := range c.files {
				if _, err := os.Stat(filepath.Join(root, rel)); err != nil {
					t.Fatalf("%s: %v", rel, err)
				}
			}
			for _, name := range c.tests {
				found := false
				for _, rel := range c.files {
					b, err := os.ReadFile(filepath.Join(root, rel))
					if err != nil {
						continue
					}
					if strings.Contains(string(b), "func "+name+"(") {
						found = true
						break
					}
				}
				if !found {
					t.Fatalf("missing %s in %v", name, c.files)
				}
			}
		})
	}
}

func repoRoot(t *testing.T) string {
	t.Helper()
	dir, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	for {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return dir
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			t.Fatal("go.mod not found")
		}
		dir = parent
	}
}
