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

func TestLoadExceptionsEmpty(t *testing.T) {
	root, err := moduleRoot()
	if err != nil {
		t.Fatal(err)
	}
	ex, err := loadExceptions(filepath.Join(root, "docs", "security", "dependency-policy.md"))
	if err != nil {
		t.Fatal(err)
	}
	if ex["CVE-0000-1"] {
		t.Fatal("unexpected exception")
	}
}
