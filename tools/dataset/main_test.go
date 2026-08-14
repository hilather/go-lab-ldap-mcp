package main

import (
	"strings"
	"testing"
)

func TestGenerateSmallScenario(t *testing.T) {
	body, err := generate("soak-lab", 10, 2, "secrets/user-alice")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(body, "name: soak-lab") {
		t.Fatal(body)
	}
	if strings.Count(body, "uid:") != 10 {
		t.Fatalf("users = %d", strings.Count(body, "uid:"))
	}
	if strings.Count(body, "id: g") != 2 {
		t.Fatalf("groups missing:\n%s", body)
	}
	if strings.Contains(body, "password:") && !strings.Contains(body, "passwordFile:") {
		t.Fatal("inline password")
	}
	if strings.Contains(body, "lab-fixture") {
		t.Fatal("fixture secret leaked into generated YAML")
	}
}

func TestGenerateRejectsTooFewUsers(t *testing.T) {
	if _, err := generate("x", 2, 5, "secrets/user-alice"); err == nil {
		t.Fatal("expected error")
	}
}
