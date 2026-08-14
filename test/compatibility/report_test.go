package compatibility

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestCompatibilityReportRecordsClientsAndEngine(t *testing.T) {
	root := repoRoot(t)
	text := read(t, filepath.Join(root, "docs", "compatibility", "ldap-clients.md"))
	for _, want := range []string{
		"ldapsearch",
		"ldapwhoami",
		"ldap3",
		"go-ldap",
		"3389",
		"3636",
		"StartTLS",
		"2.4.6",
		"v3.4.14",
		"allowAnonymousBind",
		"cn=config",
	} {
		if !strings.Contains(text, want) {
			t.Fatalf("compatibility report missing %q", want)
		}
	}
	mod := read(t, filepath.Join(root, "go.mod"))
	if !strings.Contains(mod, "github.com/go-ldap/ldap/v3 v3.4.14") {
		t.Fatal("report version must match go.mod")
	}
}

func TestIndependentClientDoesNotImportLabLDAPPool(t *testing.T) {
	root := repoRoot(t)
	src := read(t, filepath.Join(root, "test", "compatibility", "goindep", "client.go"))
	if strings.Contains(src, "hilather/go-lab-ldap-mcp/internal/") {
		t.Fatal("independent Go client must not import ldapclient")
	}
	if !strings.Contains(src, "github.com/go-ldap/ldap/v3") {
		t.Fatal("independent client must use go-ldap directly")
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
