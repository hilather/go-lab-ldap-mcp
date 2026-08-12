package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestScanFailsOnHighConfidenceSecret(t *testing.T) {
	dir := t.TempDir()
	leak := filepath.Join(dir, "leaked.env")
	// Assemble the documented AWS example key so this source file does not
	// itself match the scanner (repo scan must stay clean).
	body := "AWS_ACCESS_KEY_ID=" + "AKIA" + "IOSFODNN7EXAMPLE" + "\n"
	if err := os.WriteFile(leak, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	findings, err := scan(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(findings) == 0 {
		t.Fatal("expected fixture to fail closed")
	}
	if findings[0].rule != "aws-access-key" {
		t.Fatalf("rule = %s", findings[0].rule)
	}
}

func TestScanDoesNotPrintSecretValue(t *testing.T) {
	dir := t.TempDir()
	secret := "AKIA" + "IOSFODNN7EXAMPLE"
	if err := os.WriteFile(filepath.Join(dir, "x.txt"), []byte("id="+secret+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	findings, err := scan(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(findings) != 1 {
		t.Fatalf("findings = %#v", findings)
	}
	report := findings[0].path + findings[0].rule
	if strings.Contains(report, secret) {
		t.Fatalf("report contained secret: %#v", findings[0])
	}
}

func TestScanCleanTree(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "ok.go"), []byte("package ok\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	findings, err := scan(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(findings) != 0 {
		t.Fatalf("clean tree produced findings: %#v", findings)
	}
}
