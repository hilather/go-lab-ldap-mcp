package importboundary_test

import (
	"go/parser"
	"go/token"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestAGENTSImportBoundaries enforces T-001 / AGENTS.md package rules:
//   - no application package imports REST (internal/api) and MCP
//     (internal/mcpserver) transport types together
//   - cmd/labldap is the composition root and may import both
//   - internal/web does not import internal/app
//   - internal/config does not import LDAP packages
//   - transports do not import each other
func TestAGENTSImportBoundaries(t *testing.T) {
	t.Parallel()
	root := repoRoot(t)
	imports := collectImports(t, root)

	for pkg, imps := range imports {
		rel := strings.TrimPrefix(pkg, "github.com/hilather/go-lab-ldap-mcp/")
		hasAPI := hasImportPrefix(imps, "github.com/hilather/go-lab-ldap-mcp/internal/api")
		hasMCP := hasImportPrefix(imps, "github.com/hilather/go-lab-ldap-mcp/internal/mcpserver")
		if hasAPI && hasMCP && rel != "cmd/labldap" && !strings.HasPrefix(rel, "test/") {
			t.Errorf("%s imports both internal/api and internal/mcpserver; only cmd/labldap and tests may wire both transports", rel)
		}
		if strings.HasPrefix(rel, "internal/web") && hasImportPrefix(imps, "github.com/hilather/go-lab-ldap-mcp/internal/app") {
			t.Errorf("%s must not import internal/app (embed/static helpers only)", rel)
		}
		if strings.HasPrefix(rel, "internal/config") {
			for _, imp := range imps {
				if forbiddenConfigImport(imp) {
					t.Errorf("%s must not import LDAP or transport packages (found %s)", rel, imp)
				}
			}
		}
		if strings.HasPrefix(rel, "internal/api") && hasMCP {
			t.Errorf("%s (REST transport) must not import internal/mcpserver", rel)
		}
		if strings.HasPrefix(rel, "internal/mcpserver") && hasAPI {
			t.Errorf("%s (MCP transport) must not import internal/api", rel)
		}
		if forbiddenGoLDAP(rel, imps) {
			t.Errorf("%s must not import github.com/go-ldap/ldap (only internal/directory/ds389 and internal/directory/ldapclient may)", rel)
		}
		if forbiddenDS389Admin(rel, imps) {
			t.Errorf("%s must not import internal/directory/ds389 (bootstrap helper is command-only)", rel)
		}
		if forbiddenLDAPClient(rel, imps) {
			t.Errorf("%s must not import internal/directory/ldapclient (composition stays in cmd/labldap)", rel)
		}
		if forbiddenLDAPServer(rel, imps) {
			t.Errorf("%s must not import internal/ldapserver (only cmd/labldapd, internal/ldapserver itself, and test/ may; ADR-0009 decision 3)", rel)
		}
		if bad, found := forbiddenLDAPServerOutbound(rel, imps); found {
			t.Errorf("%s must not import %s (ADR-0009 rule 14: no transports, auth, or ds389 in ldapserver)", rel, bad)
		}
	}
}

func repoRoot(t *testing.T) string {
	t.Helper()
	dir, err := filepath.Abs("../..")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(dir, "go.mod")); err != nil {
		t.Fatalf("expected go.mod at repo root %s: %v", dir, err)
	}
	return dir
}

func collectImports(t *testing.T, root string) map[string][]string {
	t.Helper()
	fset := token.NewFileSet()
	out := map[string][]string{}
	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			name := d.Name()
			if name == "vendor" || name == "frontend" || name == ".git" || name == "node_modules" {
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(path, ".go") {
			return nil
		}
		f, err := parser.ParseFile(fset, path, nil, parser.ImportsOnly)
		if err != nil {
			return err
		}
		rel, err := filepath.Rel(root, filepath.Dir(path))
		if err != nil {
			return err
		}
		pkg := "github.com/hilather/go-lab-ldap-mcp"
		if rel != "." {
			pkg += "/" + filepath.ToSlash(rel)
		}
		seen := map[string]struct{}{}
		for _, existing := range out[pkg] {
			seen[existing] = struct{}{}
		}
		for _, spec := range f.Imports {
			imp := strings.Trim(spec.Path.Value, `"`)
			if _, ok := seen[imp]; ok {
				continue
			}
			seen[imp] = struct{}{}
			out[pkg] = append(out[pkg], imp)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	return out
}

func hasImportPrefix(imps []string, prefix string) bool {
	for _, imp := range imps {
		if imp == prefix || strings.HasPrefix(imp, prefix+"/") {
			return true
		}
	}
	return false
}

func TestKDR15LDAPImportEdges(t *testing.T) {
	t.Parallel()
	ldap := []string{"github.com/go-ldap/ldap/v3"}
	if forbiddenGoLDAP("internal/directory/ldapclient", ldap) {
		t.Fatal("ldapclient must be allowed to import go-ldap")
	}
	if forbiddenGoLDAP("internal/directory/ds389", ldap) {
		t.Fatal("ds389 must remain allowed to import go-ldap")
	}
	for _, rel := range []string{
		"internal/directory",
		"internal/app",
		"internal/api",
		"internal/mcpserver",
		"internal/auth",
		"internal/audit",
		"internal/reset",
		"internal/web",
		"cmd/labldap",
	} {
		if !forbiddenGoLDAP(rel, ldap) {
			t.Errorf("%s must not import go-ldap", rel)
		}
	}
}

func TestKDR15DS389ImportEdges(t *testing.T) {
	t.Parallel()
	ds := []string{"github.com/hilather/go-lab-ldap-mcp/internal/directory/ds389"}
	for _, rel := range []string{
		"internal/directory/ds389",
		"cmd/labldap-bootstrap",
		"cmd/labldap",
		"test/integration/dirsrv",
	} {
		if forbiddenDS389Admin(rel, ds) {
			t.Errorf("%s must remain allowed to import ds389", rel)
		}
	}
	for _, rel := range []string{
		"internal/directory",
		"internal/directory/ldapclient",
		"internal/app",
		"internal/api",
		"internal/mcpserver",
		"internal/auth",
		"internal/audit",
		"internal/reset",
		"internal/web",
	} {
		if !forbiddenDS389Admin(rel, ds) {
			t.Errorf("%s must not import ds389", rel)
		}
	}
}

func TestForbiddenConfigImport(t *testing.T) {
	t.Parallel()
	allow := []string{
		"github.com/hilather/go-lab-ldap-mcp/internal/config/v1alpha1",
		"github.com/hilather/go-lab-ldap-mcp/internal/app",
		"github.com/hilather/go-lab-ldap-mcp/internal/observability",
	}
	deny := []string{
		"github.com/hilather/go-lab-ldap-mcp/internal/directory",
		"github.com/hilather/go-lab-ldap-mcp/internal/directory/ds389",
		"github.com/hilather/go-lab-ldap-mcp/internal/api",
		"github.com/go-ldap/ldap/v3",
		"gopkg.in/ldap.v3",
	}
	for _, imp := range allow {
		if forbiddenConfigImport(imp) {
			t.Errorf("allowed import treated as forbidden: %s", imp)
		}
	}
	for _, imp := range deny {
		if !forbiddenConfigImport(imp) {
			t.Errorf("forbidden import treated as allowed: %s", imp)
		}
	}
}

func TestKDR8LDAPClientImportEdges(t *testing.T) {
	t.Parallel()
	lc := []string{"github.com/hilather/go-lab-ldap-mcp/internal/directory/ldapclient"}
	for _, rel := range []string{
		"internal/directory/ldapclient",
		"internal/directory/ds389",
		"cmd/labldap",
		"test/integration/dirsrv",
	} {
		if forbiddenLDAPClient(rel, lc) {
			t.Errorf("%s must remain allowed to import ldapclient", rel)
		}
	}
	for _, rel := range []string{
		"internal/directory",
		"internal/app",
		"internal/api",
		"internal/mcpserver",
		"internal/auth",
		"internal/audit",
		"internal/reset",
		"internal/web",
	} {
		if !forbiddenLDAPClient(rel, lc) {
			t.Errorf("%s must not import ldapclient", rel)
		}
	}
}

func TestLDAPServerImportEdges(t *testing.T) {
	t.Parallel()
	ls := []string{"github.com/hilather/go-lab-ldap-mcp/internal/ldapserver"}
	for _, rel := range []string{
		"internal/ldapserver",
		"internal/ldapserver/store",
		"cmd/labldapd",
		"test/parity",
	} {
		if forbiddenLDAPServer(rel, ls) {
			t.Errorf("%s must remain allowed to import ldapserver", rel)
		}
	}
	for _, rel := range []string{
		"cmd/labldap",
		"cmd/labldap-bootstrap",
		"internal/directory",
		"internal/directory/ds389",
		"internal/directory/ldapclient",
		"internal/directory/native",
		"internal/app",
		"internal/api",
		"internal/mcpserver",
		"internal/auth",
		"internal/audit",
		"internal/reset",
		"internal/web",
	} {
		if !forbiddenLDAPServer(rel, ls) {
			t.Errorf("%s must not import ldapserver", rel)
		}
	}
}

func TestLDAPServerOutboundEdges(t *testing.T) {
	t.Parallel()
	for _, bad := range []string{
		"github.com/hilather/go-lab-ldap-mcp/internal/api",
		"github.com/hilather/go-lab-ldap-mcp/internal/mcpserver",
		"github.com/hilather/go-lab-ldap-mcp/internal/web",
		"github.com/hilather/go-lab-ldap-mcp/internal/auth",
		"github.com/hilather/go-lab-ldap-mcp/internal/directory/ds389",
	} {
		if _, found := forbiddenLDAPServerOutbound("internal/ldapserver", []string{bad}); !found {
			t.Errorf("ldapserver importing %s must be flagged", bad)
		}
	}
	for _, good := range []string{
		"github.com/hilather/go-lab-ldap-mcp/internal/config",
		"github.com/hilather/go-lab-ldap-mcp/internal/apperr",
		"github.com/hilather/go-lab-ldap-mcp/internal/observability",
		"github.com/go-asn1-ber/asn1-ber",
	} {
		if _, found := forbiddenLDAPServerOutbound("internal/ldapserver", []string{good}); found {
			t.Errorf("ldapserver importing %s must stay allowed", good)
		}
	}
	// The outbound rule applies to ldapserver only.
	if _, found := forbiddenLDAPServerOutbound("internal/app", []string{
		"github.com/hilather/go-lab-ldap-mcp/internal/api",
	}); found {
		t.Error("outbound rule must not constrain non-ldapserver packages")
	}
}

func forbiddenGoLDAP(rel string, imps []string) bool {
	switch {
	case strings.HasPrefix(rel, "test/"):
		// Independent compatibility clients (T-115) and engine tests may use go-ldap.
		return false
	case rel == "internal/directory/ds389" || strings.HasPrefix(rel, "internal/directory/ds389/"):
		return false
	case rel == "internal/directory/ldapclient" || strings.HasPrefix(rel, "internal/directory/ldapclient/"):
		return false
	}
	return hasImportPrefix(imps, "github.com/go-ldap/ldap")
}

func forbiddenDS389Admin(rel string, imps []string) bool {
	switch {
	case strings.HasPrefix(rel, "test/"):
		return false
	case rel == "cmd/labldap-bootstrap" || strings.HasPrefix(rel, "cmd/labldap-bootstrap/"):
		return false
	case rel == "cmd/labldap" || strings.HasPrefix(rel, "cmd/labldap/"):
		return false
	case rel == "internal/directory/ds389" || strings.HasPrefix(rel, "internal/directory/ds389/"):
		return false
	}
	return hasImportPrefix(imps, "github.com/hilather/go-lab-ldap-mcp/internal/directory/ds389")
}

func forbiddenLDAPClient(rel string, imps []string) bool {
	switch {
	case strings.HasPrefix(rel, "test/"):
		return false
	case rel == "cmd/labldap" || strings.HasPrefix(rel, "cmd/labldap/"):
		return false
	case rel == "internal/directory/ldapclient" || strings.HasPrefix(rel, "internal/directory/ldapclient/"):
		return false
	case rel == "internal/directory/ds389" || strings.HasPrefix(rel, "internal/directory/ds389/"):
		return false
	}
	return hasImportPrefix(imps, "github.com/hilather/go-lab-ldap-mcp/internal/directory/ldapclient")
}

func forbiddenLDAPServer(rel string, imps []string) bool {
	switch {
	case strings.HasPrefix(rel, "test/"):
		// In-process parity and engine tests may embed the server (ADR-0009
		// decision 3).
		return false
	case rel == "cmd/labldapd" || strings.HasPrefix(rel, "cmd/labldapd/"):
		return false
	case rel == "internal/ldapserver" || strings.HasPrefix(rel, "internal/ldapserver/"):
		return false
	}
	return hasImportPrefix(imps, "github.com/hilather/go-lab-ldap-mcp/internal/ldapserver")
}

func forbiddenLDAPServerOutbound(rel string, imps []string) (string, bool) {
	if !strings.HasPrefix(rel, "internal/ldapserver") {
		return "", false
	}
	for _, bad := range []string{
		"github.com/hilather/go-lab-ldap-mcp/internal/api",
		"github.com/hilather/go-lab-ldap-mcp/internal/mcpserver",
		"github.com/hilather/go-lab-ldap-mcp/internal/web",
		"github.com/hilather/go-lab-ldap-mcp/internal/auth",
		"github.com/hilather/go-lab-ldap-mcp/internal/directory/ds389",
	} {
		if hasImportPrefix(imps, bad) {
			return bad, true
		}
	}
	return "", false
}

func forbiddenConfigImport(imp string) bool {
	prefixes := []string{
		"github.com/hilather/go-lab-ldap-mcp/internal/directory",
		"github.com/hilather/go-lab-ldap-mcp/internal/api",
		"github.com/hilather/go-lab-ldap-mcp/internal/mcpserver",
		"github.com/go-ldap/ldap",
		"gopkg.in/ldap.v3",
	}
	for _, prefix := range prefixes {
		if imp == prefix || strings.HasPrefix(imp, prefix+"/") {
			return true
		}
	}
	return false
}
