// labldap-archcheck records upstream platforms for pinned images and
// fails if advertised architectures are not present on the dirsrv digest.
package main

import (
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
)

func main() {
	os.Exit(run(os.Stdout, os.Stderr))
}

func run(stdout, stderr *os.File) int {
	root, err := moduleRoot()
	if err != nil {
		fmt.Fprintf(stderr, "archcheck: %v\n", err)
		return 1
	}
	rep, err := inspect(root)
	if err != nil {
		fmt.Fprintf(stderr, "archcheck: %v\n", err)
		return 1
	}
	if err := validate(rep); err != nil {
		fmt.Fprintf(stderr, "archcheck: %v\n", err)
		return 1
	}
	enc := json.NewEncoder(stdout)
	enc.SetIndent("", "  ")
	if err := enc.Encode(rep); err != nil {
		fmt.Fprintf(stderr, "archcheck: encode: %v\n", err)
		return 1
	}
	return 0
}

type report struct {
	DirsrvDigest      string   `json:"dirsrvDigest"`
	UpstreamPlatforms []string `json:"upstreamPlatforms"`
	Advertised        []string `json:"advertised"`
	TestedHere        []string `json:"testedHere"`
	HostArch          string   `json:"hostArch"`
	Residual          string   `json:"residual,omitempty"`
}

func inspect(root string) (report, error) {
	pin := strings.TrimSpace(mustRead(filepath.Join(root, "deploy", "docker", "dirsrv.digest")))
	adv := advertisedFromFile(filepath.Join(root, "deploy", "docker", "architectures.md"))
	host := hostArch()
	recorded := recordedPlatforms(filepath.Join(root, "deploy", "docker", "dirsrv-platforms.txt"))
	up, err := upstreamPlatforms(pin)
	if err != nil {
		if len(recorded) == 0 {
			return report{}, err
		}
		up = recorded
	}
	rep := report{
		DirsrvDigest:      pin,
		UpstreamPlatforms: up,
		Advertised:        adv,
		TestedHere:        []string{"linux/" + host},
		HostArch:          host,
	}
	if !contains(up, "linux/arm64") {
		rep.Residual = "pinned dirsrv digest has no linux/arm64; do not advertise it"
	} else if !contains(rep.Advertised, "linux/arm64") {
		rep.Residual = "upstream digest includes linux/arm64; not advertised until an arm64 smoke test runs"
	}
	return rep, nil
}

func validate(rep report) error {
	for _, a := range rep.Advertised {
		if !contains(rep.UpstreamPlatforms, a) {
			return fmt.Errorf("advertised %s is not on the pinned dirsrv digest", a)
		}
	}
	if !contains(rep.Advertised, "linux/"+rep.HostArch) && !contains(rep.Advertised, "linux/amd64") {
		return fmt.Errorf("advertised list %v does not include a tested host architecture", rep.Advertised)
	}
	return nil
}

func advertisedFromFile(path string) []string {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil
	}
	var out []string
	for _, line := range strings.Split(string(b), "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "- linux/") {
			out = append(out, strings.TrimPrefix(line, "- "))
		}
	}
	sort.Strings(out)
	return out
}

func recordedPlatforms(path string) []string {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil
	}
	var out []string
	for _, line := range strings.Split(string(b), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		out = append(out, line)
	}
	sort.Strings(out)
	return out
}

func upstreamPlatforms(ref string) ([]string, error) {
	cmd := exec.Command("docker", "manifest", "inspect", ref)
	out, err := cmd.CombinedOutput()
	if err != nil {
		// Offline or no registry: fall back to the locally loaded image.
		local, lerr := localPlatform(ref)
		if lerr != nil {
			return nil, fmt.Errorf("manifest inspect: %w (%s); local inspect: %v", err, bytesPreview(out), lerr)
		}
		return local, nil
	}
	var doc struct {
		Manifests []struct {
			Platform struct {
				Architecture string `json:"architecture"`
				OS           string `json:"os"`
			} `json:"platform"`
		} `json:"manifests"`
		Architecture string `json:"architecture"`
		OS           string `json:"os"`
	}
	if err := json.Unmarshal(out, &doc); err != nil {
		return nil, err
	}
	var plats []string
	for _, m := range doc.Manifests {
		if m.Platform.OS == "" || m.Platform.Architecture == "" {
			continue
		}
		plats = append(plats, m.Platform.OS+"/"+m.Platform.Architecture)
	}
	if len(plats) == 0 && doc.Architecture != "" {
		osName := doc.OS
		if osName == "" {
			osName = "linux"
		}
		plats = []string{osName + "/" + doc.Architecture}
	}
	sort.Strings(plats)
	return unique(plats), nil
}

func localPlatform(ref string) ([]string, error) {
	out, err := exec.Command("docker", "image", "inspect", "--format", "{{.Os}}/{{.Architecture}}", ref).Output()
	if err != nil {
		return nil, err
	}
	p := strings.TrimSpace(string(out))
	if p == "" || p == "/" {
		return nil, fmt.Errorf("empty local platform")
	}
	return []string{p}, nil
}

func hostArch() string {
	out, err := exec.Command("docker", "version", "--format", "{{.Server.Arch}}").Output()
	if err == nil {
		if a := strings.TrimSpace(string(out)); a != "" {
			return a
		}
	}
	return "amd64"
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
	sort.Strings(out)
	return out
}

func contains(in []string, want string) bool {
	for _, s := range in {
		if s == want {
			return true
		}
	}
	return false
}

func mustRead(path string) string {
	b, err := os.ReadFile(path)
	if err != nil {
		return ""
	}
	return string(b)
}

func bytesPreview(b []byte) string {
	s := strings.TrimSpace(string(b))
	if len(s) > 240 {
		return s[:240]
	}
	return s
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
