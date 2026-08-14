package main

import (
	"path/filepath"
	"testing"
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

func TestLoadExceptionsIncludesPinnedStdlib(t *testing.T) {
	root, err := moduleRoot()
	if err != nil {
		t.Fatal(err)
	}
	ex, err := loadExceptions(filepath.Join(root, "docs", "security", "dependency-policy.md"))
	if err != nil {
		t.Fatal(err)
	}
	if !ex["GO-2026-6090"] || !ex["GO-2026-6089"] || !ex["GO-2026-5972"] {
		t.Fatalf("missing stdlib exceptions: %v", ex)
	}
	if ex["CVE-0000-1"] {
		t.Fatal("unexpected exception")
	}
}

func TestParseGovulnIDs(t *testing.T) {
	text := "Vulnerability #1: GO-2026-6090\nVulnerability #2: GO-2026-6089\n"
	ids := unique(govulnIDs(text))
	if len(ids) != 2 || ids[0] != "GO-2026-6090" || ids[1] != "GO-2026-6089" {
		t.Fatalf("ids = %v", ids)
	}
}
