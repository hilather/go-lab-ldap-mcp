// labldap-releasecheck writes provenance and SHA-256 checksums that link
// artifacts to the source revision. It does not invent a LICENSE.
package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

func main() {
	os.Exit(run(os.Args[1:]))
}

func run(args []string) int {
	dir := "dist/release"
	if len(args) > 0 {
		dir = args[0]
	}
	root, err := moduleRoot()
	if err != nil {
		fmt.Fprintf(os.Stderr, "releasecheck: %v\n", err)
		return 1
	}
	if err := os.MkdirAll(dir, 0o755); err != nil {
		fmt.Fprintf(os.Stderr, "releasecheck: %v\n", err)
		return 1
	}
	prov, err := provenance(root)
	if err != nil {
		fmt.Fprintf(os.Stderr, "releasecheck: provenance: %v\n", err)
		return 1
	}
	raw, err := json.MarshalIndent(prov, "", "  ")
	if err != nil {
		fmt.Fprintf(os.Stderr, "releasecheck: %v\n", err)
		return 1
	}
	raw = append(raw, '\n')
	provPath := filepath.Join(dir, "provenance.json")
	if err := os.WriteFile(provPath, raw, 0o644); err != nil {
		fmt.Fprintf(os.Stderr, "releasecheck: %v\n", err)
		return 1
	}
	files := checksumTargets(root, dir)
	sumPath := filepath.Join(dir, "SHA256SUMS")
	if err := writeChecksums(sumPath, files); err != nil {
		fmt.Fprintf(os.Stderr, "releasecheck: checksums: %v\n", err)
		return 1
	}
	fmt.Printf("releasecheck: wrote %s and %s revision=%s\n", provPath, sumPath, prov.SourceRevision)
	return 0
}

type provenanceDoc struct {
	SourceRevision string            `json:"sourceRevision"`
	SourceDirty    bool              `json:"sourceDirty"`
	BuiltAt        string            `json:"builtAt"`
	Workflow       string            `json:"workflow"`
	DirsrvDigest   string            `json:"dirsrvDigest"`
	Images         map[string]string `json:"images"`
	Artifacts      []string          `json:"artifacts"`
}

func provenance(root string) (provenanceDoc, error) {
	rev, dirty := gitState(root)
	doc := provenanceDoc{
		SourceRevision: rev,
		SourceDirty:    dirty,
		BuiltAt:        time.Now().UTC().Format(time.RFC3339),
		Workflow:       ".github/workflows/ci.yml",
		DirsrvDigest:   strings.TrimSpace(readFile(filepath.Join(root, "deploy", "docker", "dirsrv.digest"))),
		Images:         map[string]string{},
		Artifacts: []string{
			"api/openapi.yaml",
			"deploy/compose/compose.yaml",
			"deploy/docker/dirsrv.digest",
			"deploy/docker/architectures.md",
		},
	}
	for _, img := range []string{"labldap-control:dev", "labldap-bootstrap:dev"} {
		id, err := imageID(img)
		if err != nil {
			doc.Images[img] = "absent"
			continue
		}
		doc.Images[img] = id
	}
	return doc, nil
}

type checksumFile struct {
	abs, rel string
}

func checksumTargets(root, extraDir string) []checksumFile {
	rels := []string{
		"api/openapi.yaml",
		"deploy/compose/compose.yaml",
		"deploy/compose/compose.ephemeral.yaml",
		"deploy/compose/compose.persistent.yaml",
		"deploy/compose/compose.389ds.yaml",
		"deploy/compose/compose.389ds-ephemeral.yaml",
		"deploy/compose/compose.389ds-persistent.yaml",
		"deploy/docker/dirsrv.digest",
		"deploy/docker/golang.digest",
		"deploy/docker/node.digest",
		"deploy/docker/alpine.digest",
		"deploy/docker/architectures.md",
		"go.mod",
		"go.sum",
	}
	var out []checksumFile
	for _, rel := range rels {
		out = append(out, checksumFile{abs: filepath.Join(root, rel), rel: filepath.ToSlash(rel)})
	}
	sbomRel := filepath.ToSlash(filepath.Join("dist", "sbom", "source.cdx.json"))
	if _, err := os.Stat(filepath.Join(root, filepath.FromSlash(sbomRel))); err == nil {
		out = append(out, checksumFile{abs: filepath.Join(root, filepath.FromSlash(sbomRel)), rel: sbomRel})
	}
	if _, err := os.Stat(filepath.Join(extraDir, "provenance.json")); err == nil {
		out = append(out, checksumFile{abs: filepath.Join(extraDir, "provenance.json"), rel: "dist/release/provenance.json"})
	}
	return out
}

func writeChecksums(path string, files []checksumFile) error {
	type row struct{ sum, name string }
	var rows []row
	for _, f := range files {
		sum, err := fileSHA256(f.abs)
		if err != nil {
			return err
		}
		if filepath.IsAbs(f.rel) {
			return fmt.Errorf("checksum path must be repo-relative: %s", f.rel)
		}
		rows = append(rows, row{sum: sum, name: f.rel})
	}
	sort.Slice(rows, func(i, j int) bool { return rows[i].name < rows[j].name })
	var b strings.Builder
	for _, r := range rows {
		fmt.Fprintf(&b, "%s  %s\n", r.sum, r.name)
	}
	return os.WriteFile(path, []byte(b.String()), 0o644)
}

func fileSHA256(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

func imageID(tag string) (string, error) {
	out, err := exec.Command("docker", "image", "inspect", "--format", "{{.Id}}", tag).Output()
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(string(out)), nil
}

func gitState(root string) (rev string, dirty bool) {
	cmd := exec.Command("git", "rev-parse", "HEAD")
	cmd.Dir = root
	out, err := cmd.Output()
	if err != nil {
		return "unknown", false
	}
	rev = strings.TrimSpace(string(out))
	st := exec.Command("git", "status", "--porcelain")
	st.Dir = root
	s, err := st.Output()
	if err == nil && len(bytesTrim(s)) > 0 {
		dirty = true
	}
	return rev, dirty
}

func bytesTrim(b []byte) []byte {
	return []byte(strings.TrimSpace(string(b)))
}

func readFile(path string) string {
	b, err := os.ReadFile(path)
	if err != nil {
		return ""
	}
	return string(b)
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
