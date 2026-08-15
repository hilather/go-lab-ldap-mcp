package release

import (
	"path/filepath"
	"strings"
	"testing"
)

func TestPagesWorkflowDoesNotCreateTheSite(t *testing.T) {
	wf := read(t, filepath.Join(repoRoot(t), ".github", "workflows", "pages.yml"))
	for _, line := range strings.Split(wf, "\n") {
		trim := strings.TrimSpace(line)
		if strings.HasPrefix(trim, "#") {
			continue
		}
		if strings.HasPrefix(trim, "enablement:") {
			t.Fatal("pages.yml must not pass enablement; GITHUB_TOKEN cannot create a Pages site")
		}
	}
	for _, want := range []string{
		"branches:",
		"- main",
		"build_type=workflow",
		"persist-credentials: false",
		"path: docs",
		"Require Pages GitHub Actions source",
	} {
		if !strings.Contains(wf, want) {
			t.Fatalf("pages.yml missing %q", want)
		}
	}
}

func TestCIWorkflowCancelsSupersededRuns(t *testing.T) {
	wf := read(t, filepath.Join(repoRoot(t), ".github", "workflows", "ci.yml"))
	if !strings.Contains(wf, "cancel-in-progress: true") {
		t.Fatal("ci.yml must cancel superseded runs so docs pushes do not stack integration jobs")
	}
	if !strings.Contains(wf, "needs.changes.outputs.heavy") {
		t.Fatal("ci.yml must skip integration/image when the compare range is docs-only")
	}
}

func TestPagesSiteHasStaticEntryPoints(t *testing.T) {
	root := repoRoot(t)
	for _, rel := range []string{
		"docs/index.html",
		"docs/.nojekyll",
		"docs/site.css",
		"docs/start.html",
		"docs/use.html",
		"docs/scenario.html",
		"docs/ship.html",
		"docs/assets/mark.svg",
	} {
		_ = read(t, filepath.Join(root, rel))
	}
	index := read(t, filepath.Join(root, "docs", "index.html"))
	for _, want := range []string{"start.html", "use.html", "scenario.html", "ship.html", "site.css"} {
		if !strings.Contains(index, want) {
			t.Fatalf("docs/index.html missing %q", want)
		}
	}
}
