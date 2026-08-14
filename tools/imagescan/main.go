// labldap-imagescan fails the release gate on unapproved critical findings.
// It always runs govulncheck. When grype and local images exist it scans
// those too. Exceptions live in docs/security/dependency-policy.md.
package main

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
)

const govulncheckMod = "golang.org/x/vuln/cmd/govulncheck@v1.1.4"

func main() {
	os.Exit(run(os.Stdout, os.Stderr))
}

func run(stdout, stderr *os.File) int {
	root, err := moduleRoot()
	if err != nil {
		fmt.Fprintf(stderr, "imagescan: %v\n", err)
		return 1
	}
	exceptions, err := loadExceptions(filepath.Join(root, "docs", "security", "dependency-policy.md"))
	if err != nil {
		fmt.Fprintf(stderr, "imagescan: exceptions: %v\n", err)
		return 1
	}
	if err := runGovulncheck(root, exceptions, stdout, stderr); err != nil {
		fmt.Fprintf(stderr, "imagescan: govulncheck: %v\n", err)
		return 1
	}
	if err := runGrypeIfPresent(root, exceptions, stdout, stderr); err != nil {
		fmt.Fprintf(stderr, "imagescan: %v\n", err)
		return 1
	}
	fmt.Fprintln(stdout, "imagescan: ok")
	return 0
}

var govulnID = regexp.MustCompile(`(?m)^Vulnerability #\d+: (GO-\d{4}-\d+)\b`)

func govulnIDs(text string) []string {
	var ids []string
	for _, m := range govulnID.FindAllStringSubmatch(text, -1) {
		if len(m) > 1 {
			ids = append(ids, m[1])
		}
	}
	return ids
}

func runGovulncheck(root string, exceptions map[string]bool, stdout, stderr *os.File) error {
	cmd := exec.Command("go", "run", govulncheckMod, "./...")
	cmd.Dir = root
	cmd.Env = append(os.Environ(), "GOTOOLCHAIN=go1.26.5")
	out, err := cmd.CombinedOutput()
	_, _ = stdout.Write(out)
	if err == nil {
		return nil
	}
	ids := unique(govulnIDs(string(out)))
	var unapproved []string
	for _, id := range ids {
		if exceptions[id] {
			fmt.Fprintf(stdout, "imagescan: approved exception %s\n", id)
			continue
		}
		unapproved = append(unapproved, id)
	}
	if len(unapproved) > 0 {
		return fmt.Errorf("unapproved findings: %s", strings.Join(unapproved, ", "))
	}
	if len(ids) == 0 {
		return fmt.Errorf("govulncheck failed without parseable IDs: %w", err)
	}
	return nil
}

func unique(in []string) []string {
	seen := map[string]bool{}
	var out []string
	for _, s := range in {
		if seen[s] {
			continue
		}
		seen[s] = true
		out = append(out, s)
	}
	return out
}

func runGrypeIfPresent(root string, exceptions map[string]bool, stdout, stderr *os.File) error {
	if _, err := exec.LookPath("grype"); err != nil {
		fmt.Fprintln(stdout, "imagescan: grype not on PATH; source govulncheck is the critical gate")
		return nil
	}
	for _, img := range []string{"labldap-control:dev", "labldap-bootstrap:dev"} {
		if exec.Command("docker", "image", "inspect", img).Run() != nil {
			fmt.Fprintf(stdout, "imagescan: skip grype %s (image not present)\n", img)
			continue
		}
		cmd := exec.Command("grype", img, "-o", "json")
		cmd.Dir = root
		out, err := cmd.CombinedOutput()
		if err != nil && !json.Valid(bytes.TrimSpace(out)) {
			return fmt.Errorf("grype %s: %w\n%s", img, err, out)
		}
		crits, err := criticalIDs(out)
		if err != nil {
			return fmt.Errorf("grype %s parse: %w", img, err)
		}
		var unapproved []string
		for _, id := range crits {
			if exceptions[id] {
				fmt.Fprintf(stdout, "imagescan: approved exception %s on %s\n", id, img)
				continue
			}
			unapproved = append(unapproved, id)
		}
		if len(unapproved) > 0 {
			return fmt.Errorf("unapproved critical findings on %s: %s", img, strings.Join(unapproved, ", "))
		}
	}
	return nil
}

func criticalIDs(raw []byte) ([]string, error) {
	var doc struct {
		Matches []struct {
			Vulnerability struct {
				ID         string `json:"id"`
				Severity   string `json:"severity"`
				Fix        any    `json:"fix"`
				DataSource string `json:"dataSource"`
			} `json:"vulnerability"`
		} `json:"matches"`
	}
	if err := json.Unmarshal(raw, &doc); err != nil {
		return nil, err
	}
	var ids []string
	seen := map[string]bool{}
	for _, m := range doc.Matches {
		sev := strings.ToLower(m.Vulnerability.Severity)
		if sev != "critical" {
			continue
		}
		id := strings.TrimSpace(m.Vulnerability.ID)
		if id == "" || seen[id] {
			continue
		}
		seen[id] = true
		ids = append(ids, id)
	}
	return ids, nil
}

func loadExceptions(path string) (map[string]bool, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	out := map[string]bool{}
	sc := bufio.NewScanner(f)
	in := false
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "## Approved exceptions" {
			in = true
			continue
		}
		if in && strings.HasPrefix(line, "## ") {
			break
		}
		if !in || !strings.HasPrefix(line, "|") {
			continue
		}
		cols := strings.Split(line, "|")
		if len(cols) < 3 {
			continue
		}
		id := strings.TrimSpace(cols[1])
		if id == "" || id == "ID" || strings.HasPrefix(id, "---") {
			continue
		}
		out[id] = true
	}
	return out, sc.Err()
}

func moduleRoot() (string, error) {
	dir, err := os.Getwd()
	if err != nil {
		return "", err
	}
	for {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return dir, nil
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			return "", fmt.Errorf("go.mod not found")
		}
		dir = parent
	}
}
