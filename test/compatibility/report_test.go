package compatibility

import (
	"os"
	"os/exec"
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
		"--server-name",
		"ldap-utils",
		"IP SAN",
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

func TestPythonClientTLSNamesIncludeServerNameForIPURL(t *testing.T) {
	if _, err := exec.LookPath("python3"); err != nil {
		t.Skip("python3 not on PATH")
	}
	script := filepath.Join(repoRoot(t), "test", "compatibility", "clients", "python", "client.py")
	cmd := exec.Command("python3", script, "--print-valid-names",
		"--url", "ldaps://127.0.0.1:3636", "--server-name", "localhost")
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("print-valid-names: %v\n%s", err, out)
	}
	got := strings.Split(strings.TrimSpace(string(out)), "\n")
	if len(got) < 1 || got[0] != "localhost" {
		t.Fatalf("first valid name must be --server-name localhost, got %q", got)
	}
	joined := strings.Join(got, ",")
	if !strings.Contains(joined, "127.0.0.1") {
		t.Fatalf("valid names should still include the URL host, got %q", got)
	}
}

func TestCompatSuiteDoesNotUseInContainerPasswordModify(t *testing.T) {
	src := read(t, filepath.Join(repoRoot(t), "test", "integration", "dirsrv", "compat_test.go"))
	if !strings.Contains(src, `"ldapmodify"`) {
		t.Fatal("compat suite must invoke host ldapmodify")
	}
	if strings.Contains(src, "docker\", \"exec\", \"-i\"") {
		t.Fatal("password modify must not docker-exec ldapmodify; host OpenLDAP -y is the T-115 client")
	}
	if !strings.Contains(src, `"--server-name", "localhost"`) {
		t.Fatal("python_ldap3 must pass --server-name localhost (ldap3 ignores IP SANs)")
	}
	if !strings.Contains(src, "requireHostTool") {
		t.Fatal("compat suite must fail in CI when host LDAP clients are missing")
	}
	if strings.Contains(src, `value+"\n"`) || strings.Contains(src, "value+\"\\n\"") {
		t.Fatal("writePW must not append a newline; OpenLDAP 2.6 -y sends the complete file as the password")
	}
}

func TestPythonClientUsesContractAttributes(t *testing.T) {
	src := read(t, filepath.Join(repoRoot(t), "test", "compatibility", "clients", "python", "client.py"))
	if strings.Contains(src, `attributes=["entryDN"]`) || strings.Contains(src, "attributes=['entryDN']") {
		t.Fatal("python ldap3 client must not request 389-only entryDN (parity D6); use uid")
	}
	if !strings.Contains(src, `attributes=["uid"]`) && !strings.Contains(src, "attributes=['uid']") {
		t.Fatal("python ldap3 client must search a contract attribute (uid)")
	}
	if strings.Contains(src, "get_info=ALL") {
		t.Fatal("ldap3 get_info=ALL schema-validates against advertised types and rejects native (no entryDN)")
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
