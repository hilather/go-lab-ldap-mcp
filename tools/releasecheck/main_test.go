package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestRunWritesProvenanceAndSums(t *testing.T) {
	dir := t.TempDir()
	if code := run([]string{dir}); code != 0 {
		t.Fatalf("exit %d", code)
	}
	raw, err := os.ReadFile(filepath.Join(dir, "provenance.json"))
	if err != nil {
		t.Fatal(err)
	}
	var doc provenanceDoc
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatal(err)
	}
	if doc.SourceRevision == "" || doc.DirsrvDigest == "" {
		t.Fatalf("incomplete provenance: %+v", doc)
	}
	if !strings.Contains(doc.DirsrvDigest, "@sha256:") {
		t.Fatalf("dirsrv digest = %s", doc.DirsrvDigest)
	}
	if doc.Workflow != ".github/workflows/ci.yml" {
		t.Fatalf("workflow = %s", doc.Workflow)
	}
	sums, err := os.ReadFile(filepath.Join(dir, "SHA256SUMS"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(sums), "openapi.yaml") {
		t.Fatalf("checksums:\n%s", sums)
	}
}
