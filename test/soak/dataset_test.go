package soak

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/hilather/go-lab-ldap-mcp/internal/config"
)

func TestGeneratedSmallDatasetCompiles(t *testing.T) {
	root := repoRoot(t)
	out := filepath.Join(t.TempDir(), "small.yaml")
	cmd := exec.Command("go", "run", "./tools/dataset", "--users", "8", "--groups", "2",
		"--password-file", "secrets/user-alice", "--out", out)
	cmd.Dir = root
	if raw, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("dataset: %v\n%s", err, raw)
	}
	src, err := os.ReadFile(out)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := config.Compile(t.Context(), src, out, config.LoadOptions{
		Caller:  config.CallerControl,
		Secrets: config.DirSecretResolver(filepath.Join(root, "config", "examples")),
	}); err != nil {
		t.Fatal(err)
	}
}

func TestLimitsDocRecordsResidual(t *testing.T) {
	root := repoRoot(t)
	text := read(t, filepath.Join(root, "docs", "operations", "limits.md"))
	for _, want := range []string{"10,000", "1,000", "LABLDAP_SOAK_MEDIUM", "not measured"} {
		if !strings.Contains(text, want) {
			t.Fatalf("limits doc missing %q", want)
		}
	}
}

func read(t *testing.T, path string) string {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
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
