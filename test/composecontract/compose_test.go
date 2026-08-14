package composecontract

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

func TestDevComposeTopology(t *testing.T) {
	root := repoRoot(t)
	raw, err := os.ReadFile(filepath.Join(root, "deploy", "compose", "compose.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	text := string(raw)
	if strings.Contains(text, "labldap-control:dev") {
		t.Fatal("T-042 must not tag the placeholder as labldap-control:dev")
	}
	if strings.Contains(text, "docker.sock") {
		t.Fatal("compose must not mount the Docker socket")
	}

	pin, err := os.ReadFile(filepath.Join(root, "deploy", "docker", "dirsrv.digest"))
	if err != nil {
		t.Fatal(err)
	}
	digest := strings.TrimSpace(string(pin))
	if !strings.Contains(digest, "@sha256:") {
		t.Fatalf("dirsrv.digest is not a digest pin: %s", digest)
	}

	var doc struct {
		Services map[string]map[string]any `yaml:"services"`
	}
	if err := yaml.Unmarshal(raw, &doc); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"directory", "bootstrap", "control"} {
		if _, ok := doc.Services[name]; !ok {
			t.Fatalf("missing service %s", name)
		}
	}

	dir := doc.Services["directory"]
	if img, _ := dir["image"].(string); img != digest {
		t.Fatalf("directory image %q, want pinned %q", img, digest)
	}
	if _, ok := dir["env_file"]; !ok {
		t.Fatal("directory must use env_file (KD-R20)")
	}
	if env, _ := dir["environment"].(map[string]any); env != nil {
		if _, ok := env["DS_DM_PASSWORD"]; ok {
			t.Fatal("directory must not inline DS_DM_PASSWORD")
		}
	}

	boot := doc.Services["bootstrap"]
	if img, _ := boot["image"].(string); img != "labldap-bootstrap:dev" {
		t.Fatalf("bootstrap image = %q", img)
	}
	assertDepends(t, boot, "directory", "service_healthy")
	cmd := flatten(boot["command"])
	joined := strings.Join(cmd, " ")
	if !strings.Contains(joined, "apply") || !strings.Contains(joined, "--directory-manager-password-file") {
		t.Fatalf("bootstrap command = %v", cmd)
	}
	if strings.Contains(joined, "--directory-manager-password ") {
		t.Fatal("DM password must not appear on argv")
	}

	ctl := doc.Services["control"]
	if img, _ := ctl["image"].(string); img != "labldap-control:placeholder" {
		t.Fatalf("control image = %q", img)
	}
	assertDepends(t, ctl, "bootstrap", "service_completed_successfully")
	env, _ := ctl["environment"].(map[string]any)
	if env["LABLDAP_LISTEN"] != "127.0.0.1:8443" {
		t.Fatalf("LABLDAP_LISTEN = %v", env["LABLDAP_LISTEN"])
	}
	if _, ok := env["DS_DM_PASSWORD"]; ok {
		t.Fatal("control must not receive DS_DM_PASSWORD")
	}
	hc, _ := ctl["healthcheck"].(map[string]any)
	test := flatten(hc["test"])
	if !strings.Contains(strings.Join(test, " "), "/health") || strings.Contains(strings.Join(test, " "), "/health/ready") {
		t.Fatalf("control healthcheck must be GET /health only: %v", test)
	}
}

func assertDepends(t *testing.T, svc map[string]any, peer, cond string) {
	t.Helper()
	raw, ok := svc["depends_on"]
	if !ok {
		t.Fatalf("missing depends_on (want %s %s)", peer, cond)
	}
	m, ok := raw.(map[string]any)
	if !ok {
		t.Fatalf("depends_on = %#v", raw)
	}
	peerSpec, ok := m[peer].(map[string]any)
	if !ok {
		t.Fatalf("depends_on.%s = %#v", peer, m[peer])
	}
	if peerSpec["condition"] != cond {
		t.Fatalf("depends_on.%s.condition = %v, want %s", peer, peerSpec["condition"], cond)
	}
}

func flatten(v any) []string {
	switch t := v.(type) {
	case []any:
		out := make([]string, 0, len(t))
		for _, item := range t {
			out = append(out, flatten(item)...)
		}
		return out
	case string:
		return []string{t}
	default:
		return nil
	}
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
