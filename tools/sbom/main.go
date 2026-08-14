// labldap-sbom writes a source SBOM that names the pinned 389 DS digest
// and the Go / frontend module graph. Image SBOMs are produced when syft
// is on PATH (make sbom-image).
package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
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
	out := "dist/sbom/source.cdx.json"
	if len(args) > 0 {
		out = args[0]
	}
	root, err := moduleRoot()
	if err != nil {
		fmt.Fprintf(os.Stderr, "sbom: %v\n", err)
		return 1
	}
	doc, err := build(root)
	if err != nil {
		fmt.Fprintf(os.Stderr, "sbom: %v\n", err)
		return 1
	}
	if err := os.MkdirAll(filepath.Dir(out), 0o755); err != nil {
		fmt.Fprintf(os.Stderr, "sbom: %v\n", err)
		return 1
	}
	raw, err := json.MarshalIndent(doc, "", "  ")
	if err != nil {
		fmt.Fprintf(os.Stderr, "sbom: %v\n", err)
		return 1
	}
	raw = append(raw, '\n')
	if err := os.WriteFile(out, raw, 0o644); err != nil {
		fmt.Fprintf(os.Stderr, "sbom: %v\n", err)
		return 1
	}
	sum := sha256.Sum256(raw)
	fmt.Printf("sbom: wrote %s sha256:%s components=%d\n", out, hex.EncodeToString(sum[:]), len(doc.Components))
	return 0
}

type document struct {
	BOMFormat    string      `json:"bomFormat"`
	SpecVersion  string      `json:"specVersion"`
	Version      int         `json:"version"`
	Metadata     metadata    `json:"metadata"`
	Components   []component `json:"components"`
	Dependencies []depRef    `json:"dependencies,omitempty"`
}

type metadata struct {
	Timestamp string    `json:"timestamp"`
	Component component `json:"component"`
	Tools     []tool    `json:"tools"`
}

type tool struct {
	Name    string `json:"name"`
	Version string `json:"version"`
}

type component struct {
	Type       string `json:"type"`
	BOMRef     string `json:"bom-ref"`
	Name       string `json:"name"`
	Version    string `json:"version,omitempty"`
	PURL       string `json:"purl,omitempty"`
	Hashes     []hash `json:"hashes,omitempty"`
	Properties []prop `json:"properties,omitempty"`
}

type hash struct {
	Alg     string `json:"alg"`
	Content string `json:"content"`
}

type prop struct {
	Name  string `json:"name"`
	Value string `json:"value"`
}

type depRef struct {
	Ref       string   `json:"ref"`
	DependsOn []string `json:"dependsOn,omitempty"`
}

func build(root string) (document, error) {
	rev := gitRev(root)
	dirsrv := strings.TrimSpace(readFile(filepath.Join(root, "deploy", "docker", "dirsrv.digest")))
	goPin := strings.TrimSpace(readFile(filepath.Join(root, "deploy", "docker", "golang.digest")))
	nodePin := strings.TrimSpace(readFile(filepath.Join(root, "deploy", "docker", "node.digest")))
	alpinePin := strings.TrimSpace(readFile(filepath.Join(root, "deploy", "docker", "alpine.digest")))

	mods, err := goModules(root)
	if err != nil {
		return document{}, err
	}
	front, err := frontendDeps(root)
	if err != nil {
		return document{}, err
	}

	app := component{
		Type:    "application",
		BOMRef:  "pkg:github/hilather/go-lab-ldap-mcp@" + rev,
		Name:    "labldap",
		Version: rev,
		Properties: []prop{
			{Name: "labldap:dirsrv", Value: dirsrv},
			{Name: "labldap:golang-image", Value: goPin},
			{Name: "labldap:node-image", Value: nodePin},
			{Name: "labldap:alpine-image", Value: alpinePin},
		},
	}
	comps := []component{
		{
			Type:   "container",
			BOMRef: dirsrv,
			Name:   "quay.io/389ds/dirsrv",
			PURL:   "pkg:oci/dirsrv?repository_url=quay.io/389ds",
			Properties: []prop{
				{Name: "labldap:role", Value: "389ds-engine"},
				{Name: "labldap:digest", Value: dirsrv},
			},
		},
	}
	comps = append(comps, mods...)
	comps = append(comps, front...)

	var deps []string
	for _, c := range comps {
		deps = append(deps, c.BOMRef)
	}
	return document{
		BOMFormat:   "CycloneDX",
		SpecVersion: "1.5",
		Version:     1,
		Metadata: metadata{
			Timestamp: time.Now().UTC().Format(time.RFC3339),
			Component: app,
			Tools:     []tool{{Name: "labldap-sbom", Version: "T-118"}},
		},
		Components:   comps,
		Dependencies: []depRef{{Ref: app.BOMRef, DependsOn: deps}},
	}, nil
}

func goModules(root string) ([]component, error) {
	cmd := exec.Command("go", "list", "-m", "-json", "all")
	cmd.Dir = root
	cmd.Env = append(os.Environ(), "GOTOOLCHAIN=go1.26.5")
	out, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("go list: %w", err)
	}
	dec := json.NewDecoder(strings.NewReader(string(out)))
	var comps []component
	for dec.More() {
		var m struct {
			Path    string
			Version string
			Main    bool
		}
		if err := dec.Decode(&m); err != nil {
			return nil, err
		}
		if m.Path == "" {
			continue
		}
		ver := m.Version
		if ver == "" {
			ver = "main"
		}
		ref := "pkg:golang/" + m.Path + "@" + ver
		comps = append(comps, component{
			Type:    "library",
			BOMRef:  ref,
			Name:    m.Path,
			Version: ver,
			PURL:    ref,
		})
	}
	sort.Slice(comps, func(i, j int) bool { return comps[i].Name < comps[j].Name })
	return comps, nil
}

func frontendDeps(root string) ([]component, error) {
	raw, err := os.ReadFile(filepath.Join(root, "frontend", "package.json"))
	if err != nil {
		return nil, err
	}
	var pkg struct {
		Dependencies    map[string]string `json:"dependencies"`
		DevDependencies map[string]string `json:"devDependencies"`
	}
	if err := json.Unmarshal(raw, &pkg); err != nil {
		return nil, err
	}
	var comps []component
	add := func(name, ver, scope string) {
		ref := "pkg:npm/" + name + "@" + ver
		comps = append(comps, component{
			Type:    "library",
			BOMRef:  ref,
			Name:    name,
			Version: ver,
			PURL:    ref,
			Properties: []prop{
				{Name: "labldap:scope", Value: scope},
			},
		})
	}
	for n, v := range pkg.Dependencies {
		add(n, v, "runtime")
	}
	for n, v := range pkg.DevDependencies {
		add(n, v, "dev")
	}
	sort.Slice(comps, func(i, j int) bool { return comps[i].Name < comps[j].Name })
	return comps, nil
}

func gitRev(root string) string {
	cmd := exec.Command("git", "rev-parse", "HEAD")
	cmd.Dir = root
	out, err := cmd.Output()
	if err != nil {
		return "unknown"
	}
	return strings.TrimSpace(string(out))
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
