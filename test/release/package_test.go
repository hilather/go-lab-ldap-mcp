package release

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/hilather/go-lab-ldap-mcp/internal/config"
	"github.com/hilather/go-lab-ldap-mcp/internal/mcpserver"
)

func TestExamplesValidateAndHaveNoRealSecrets(t *testing.T) {
	root := repoRoot(t)
	examples := []struct {
		path string
		res  config.SecretResolver
	}{
		{
			path: filepath.Join(root, "config", "examples", "example-lab.yaml"),
			res:  config.DirSecretResolver(filepath.Join(root, "config", "examples")),
		},
		{
			path: filepath.Join(root, "deploy", "compose", "scenario.yaml"),
			res: config.MapResolver{
				"/run/secrets/runtime-ldap": "lab-fixture-runtime-password",
				"/run/secrets/user-alice":   "lab-fixture-alice-password",
				"/run/secrets/token-admin":  "lab-fixture-admin-token",
			},
		},
		{
			path: filepath.Join(root, "deploy", "compose", "scenario.persistent.yaml"),
			res: config.MapResolver{
				"/run/secrets/runtime-ldap": "lab-fixture-runtime-password",
				"/run/secrets/user-alice":   "lab-fixture-alice-password",
				"/run/secrets/token-admin":  "lab-fixture-admin-token",
			},
		},
	}
	for _, ex := range examples {
		src, err := os.ReadFile(ex.path)
		if err != nil {
			t.Fatal(err)
		}
		text := string(src)
		for _, banned := range []string{
			"-----BEGIN", "ghp_", "AKIA", "xoxb-",
		} {
			if strings.Contains(text, banned) {
				t.Fatalf("%s contains credential material %q", ex.path, banned)
			}
		}
		if _, err := config.Compile(t.Context(), src, ex.path, config.LoadOptions{
			Caller:  config.CallerControl,
			Secrets: ex.res,
		}); err != nil {
			t.Fatalf("compile %s: %v", ex.path, err)
		}
	}
	for _, name := range []string{"token-admin", "runtime-ldap", "user-alice"} {
		got := strings.TrimSpace(read(t, filepath.Join(root, "config", "examples", "secrets", name)))
		if !strings.HasPrefix(got, "lab-fixture-") {
			t.Fatalf("example secret %s must be a lab-fixture placeholder", name)
		}
	}
}

func TestOperatorGuideIsSelfContained(t *testing.T) {
	root := repoRoot(t)
	guide := read(t, filepath.Join(root, "docs", "operations", "operator-guide.md"))
	for _, want := range []string{
		"make compose-up",
		"make compose-up-persistent",
		"make compose-reset",
		"tmpfs",
		"Host swap",
		"Active Directory",
		"3389",
		"3636",
		"api/openapi.yaml",
		"config/schema/v1alpha1.json",
		"Directory Manager",
		"lab:reset",
		"linux/amd64",
	} {
		if !strings.Contains(guide, want) {
			t.Fatalf("operator guide missing %q", want)
		}
	}
	// The only permitted dsctl mention is the documented TLS import.
	if strings.Contains(guide, "dsconf") {
		t.Fatal("operator guide must not document raw dsconf")
	}
	if !strings.Contains(guide, "dsctl localhost tls import") {
		t.Fatal("operator guide must document the TLS import path")
	}
	trouble := read(t, filepath.Join(root, "docs", "operations", "troubleshooting.md"))
	if strings.Contains(trouble, "dsconf") {
		t.Fatal("troubleshooting must not invent dsconf steps")
	}
	if !strings.Contains(trouble, "Host swap") && !strings.Contains(guide, "Host swap") {
		t.Fatal("tmpfs swap caveat missing")
	}
}

func TestReleaseNotesAndChecklist(t *testing.T) {
	root := repoRoot(t)
	notes := read(t, filepath.Join(root, "docs", "release", "notes.md"))
	for _, want := range []string{
		"linux/amd64",
		"v1alpha1",
		"Active Directory",
		"MCP",
		"Migration",
		"make verify",
		"OD-004",
	} {
		if !strings.Contains(notes, want) {
			t.Fatalf("release notes missing %q", want)
		}
	}
	check := read(t, filepath.Join(root, "docs", "release", "checklist.md"))
	for _, want := range []string{
		"make verify",
		"compose-up-persistent",
		"LICENSE",
		"docker push",
		"provenance.json",
	} {
		if !strings.Contains(check, want) {
			t.Fatalf("checklist missing %q", want)
		}
	}
	cat := read(t, filepath.Join(root, "docs", "mcp", "catalog.md"))
	for _, d := range mcpserver.Catalog() {
		if !strings.Contains(cat, d.Name) {
			t.Fatalf("MCP catalog.md missing tool %s from Catalog()", d.Name)
		}
	}
	for _, r := range mcpserver.ResourceCatalog() {
		uri := r.URI
		if uri == "" {
			uri = r.URITemplate
		}
		if uri != "" && !strings.Contains(cat, uri) {
			t.Fatalf("MCP catalog.md missing resource %s", uri)
		}
	}
}

func TestPersistentUpgradeHasNoPriorAPIVersion(t *testing.T) {
	root := repoRoot(t)
	for _, rel := range []string{
		"deploy/compose/scenario.yaml",
		"deploy/compose/scenario.persistent.yaml",
		"config/examples/example-lab.yaml",
	} {
		text := read(t, filepath.Join(root, rel))
		if !strings.Contains(text, "apiVersion: labldap.dev/v1alpha1") {
			t.Fatalf("%s is not v1alpha1", rel)
		}
		if strings.Contains(text, "v1beta1") || strings.Contains(text, "v1alpha2") {
			t.Fatalf("%s introduced a new apiVersion without migration notes", rel)
		}
	}
	notes := read(t, filepath.Join(root, "docs", "release", "notes.md"))
	if !strings.Contains(notes, "no prior") && !strings.Contains(strings.ToLower(notes), "first packaged") {
		t.Fatal("release notes must say this is the first packaged release")
	}
}

func TestMakefileVerifyIsReleaseGate(t *testing.T) {
	root := repoRoot(t)
	mk := read(t, filepath.Join(root, "Makefile"))
	for _, want := range []string{"sbom", "checksums", "archcheck", "test-security"} {
		if !strings.Contains(mk, want) {
			t.Fatalf("Makefile missing %q", want)
		}
	}
	if !strings.Contains(mk, "verify: format lint generate generate-drift test-unit test-security sbom checksums archcheck") {
		t.Fatal("make verify must include SBOM, checksums, and archcheck")
	}
	if strings.Contains(mk, "WARNING test/parity") {
		t.Fatal("make verify must hard-gate test/parity, not WARNING-on-failure")
	}
	if !strings.Contains(mk, "$(MAKE) test-integration-native") {
		t.Fatal("make verify must hard-gate test-integration-native")
	}
	if !strings.Contains(mk, "go test -tags=integration ./test/parity/") {
		t.Fatal("make verify must hard-gate dual-engine test/parity when Docker is present")
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
