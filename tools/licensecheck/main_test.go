package main

import (
	"os"
	"path/filepath"
	"testing"
)

func TestRunFromModuleRoot(t *testing.T) {
	dir, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	for {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			t.Chdir(dir)
			break
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			t.Fatal("go.mod not found")
		}
		dir = parent
	}
	if err := run(); err != nil {
		t.Fatal(err)
	}
}

func TestDeniedTokens(t *testing.T) {
	if hit := deniedToken("github.com/foo/bar v1.0.0"); hit != "" {
		t.Fatalf("clean path hit %q", hit)
	}
	if hit := deniedToken("github.com/evil/agpl-lib v0.1.0"); hit == "" {
		t.Fatal("expected agpl token")
	}
}
