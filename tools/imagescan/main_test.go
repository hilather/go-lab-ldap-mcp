package main

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestCriticalIDs(t *testing.T) {
	raw := []byte(`{"matches":[
		{"vulnerability":{"id":"CVE-0000-1","severity":"Critical"}},
		{"vulnerability":{"id":"CVE-0000-2","severity":"High"}},
		{"vulnerability":{"id":"CVE-0000-1","severity":"critical"}}
	]}`)
	ids, err := criticalIDs(raw)
	if err != nil {
		t.Fatal(err)
	}
	if len(ids) != 1 || ids[0] != "CVE-0000-1" {
		t.Fatalf("ids = %v", ids)
	}
}

func TestLoadExceptionsHonorsExpiry(t *testing.T) {
	future := time.Now().UTC().Add(48 * time.Hour).Format("2006-01-02")
	policy := "# Policy\n\n## Approved exceptions\n\n" +
		"| ID | Reason | Expires |\n| --- | --- | --- |\n" +
		"| GO-0000-1 | active | " + future + " |\n" +
		"| GO-0000-2 | expired | 2000-01-01 |\n" +
		"| GO-0000-3 | no expiry | \u2014 |\n" +
		"\n## Next section\n\n| GO-0000-4 | outside table | " + future + " |\n"
	path := filepath.Join(t.TempDir(), "dependency-policy.md")
	if err := os.WriteFile(path, []byte(policy), 0o600); err != nil {
		t.Fatal(err)
	}
	ex, err := loadExceptions(path)
	if err != nil {
		t.Fatal(err)
	}
	if !ex["GO-0000-1"] || !ex["GO-0000-3"] {
		t.Fatalf("missing active exceptions: %v", ex)
	}
	if ex["GO-0000-2"] || ex["GO-0000-4"] || ex["CVE-0000-1"] || len(ex) != 2 {
		t.Fatalf("unexpected exceptions: %v", ex)
	}
}

func TestLoadExceptionsParsesPolicy(t *testing.T) {
	root, err := moduleRoot()
	if err != nil {
		t.Fatal(err)
	}
	ex, err := loadExceptions(filepath.Join(root, "docs", "security", "dependency-policy.md"))
	if err != nil {
		t.Fatal(err)
	}
	// Fixed by the go1.26.8 toolchain pin; they must not come back as approvals.
	for _, id := range []string{"GO-2026-6090", "GO-2026-6089", "GO-2026-5972", "GO-2026-6218", "GO-2026-5026"} {
		if ex[id] {
			t.Fatalf("retired stdlib exception %s is still approved", id)
		}
	}
}

func TestParseGovulnIDs(t *testing.T) {
	text := "Vulnerability #1: GO-2026-6090\nVulnerability #2: GO-2026-6089\n"
	ids := unique(govulnIDs(text))
	if len(ids) != 2 || ids[0] != "GO-2026-6090" || ids[1] != "GO-2026-6089" {
		t.Fatalf("ids = %v", ids)
	}
}
