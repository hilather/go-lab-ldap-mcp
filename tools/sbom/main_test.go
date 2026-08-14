package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestBuildNamesPinnedDirsrvAndGoModules(t *testing.T) {
	root, err := moduleRoot()
	if err != nil {
		t.Fatal(err)
	}
	doc, err := build(root)
	if err != nil {
		t.Fatal(err)
	}
	if doc.BOMFormat != "CycloneDX" {
		t.Fatalf("format = %s", doc.BOMFormat)
	}
	pin := strings.TrimSpace(readFile(filepath.Join(root, "deploy", "docker", "dirsrv.digest")))
	foundDirsrv := false
	foundLDAP := false
	for _, c := range doc.Components {
		if strings.Contains(c.BOMRef, pin) || c.Name == "quay.io/389ds/dirsrv" {
			foundDirsrv = true
		}
		if strings.Contains(c.Name, "github.com/go-ldap/ldap") {
			foundLDAP = true
		}
	}
	if !foundDirsrv {
		t.Fatal("SBOM must identify the pinned 389 DS digest")
	}
	if !foundLDAP {
		t.Fatal("SBOM must include go-ldap")
	}
	if !strings.Contains(doc.Metadata.Component.Properties[0].Value, "@sha256:") {
		t.Fatal("application metadata must record dirsrv digest")
	}
}

func TestRunWritesFile(t *testing.T) {
	out := filepath.Join(t.TempDir(), "sbom.json")
	if code := run([]string{out}); code != 0 {
		t.Fatalf("exit %d", code)
	}
	raw, err := os.ReadFile(out)
	if err != nil {
		t.Fatal(err)
	}
	var doc document
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatal(err)
	}
	if len(doc.Components) < 2 {
		t.Fatalf("components = %d", len(doc.Components))
	}
}
