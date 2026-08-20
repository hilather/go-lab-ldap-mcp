package inspect

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

// Fixture values from config/examples/secrets. These are lab placeholders
// and must not appear in image history or the control environment.
var fixtureSecrets = []string{
	"lab-fixture-admin-token",
	"lab-fixture-alice-password",
	"lab-fixture-runtime-password",
}

func TestComposeControlHardening(t *testing.T) {
	root := repoRoot(t)
	raw := read(t, filepath.Join(root, "deploy", "compose", "compose.yaml"))
	text := string(raw)
	for _, banned := range []string{"privileged: true", "privileged: \"true\"", "docker.sock", "DS_DM_PASSWORD"} {
		if strings.Contains(text, banned) && banned == "DS_DM_PASSWORD" {
			// directory.env injects DM; control must not name the variable.
			if strings.Contains(text, "control:") && controlMentions(text, "DS_DM_PASSWORD") {
				t.Fatal("control service must not mention DS_DM_PASSWORD")
			}
			continue
		}
		if banned != "DS_DM_PASSWORD" && strings.Contains(text, banned) {
			t.Fatalf("compose must not contain %q", banned)
		}
	}

	var doc struct {
		Services map[string]map[string]any `yaml:"services"`
	}
	if err := yaml.Unmarshal([]byte(raw), &doc); err != nil {
		t.Fatal(err)
	}
	ctl := doc.Services["control"]
	if ctl == nil {
		t.Fatal("missing control")
	}
	if ctl["privileged"] == true {
		t.Fatal("control must not be privileged")
	}
	if ctl["user"] != "65532:65532" {
		t.Fatalf("control user = %v", ctl["user"])
	}
	if add := flatten(ctl["cap_add"]); len(add) > 0 {
		t.Fatalf("control must not cap_add: %v", add)
	}
	if !containsExact(flatten(ctl["cap_drop"]), "ALL") {
		t.Fatalf("control cap_drop = %v", flatten(ctl["cap_drop"]))
	}
	ports := flatten(ctl["ports"])
	if !containsExact(ports, "${LABLDAP_CONTROL_PUBLISH:-127.0.0.1}:8443:8443") {
		t.Fatalf("control host port must default to loopback with LABLDAP_CONTROL_PUBLISH override: %v", ports)
	}
	dir := doc.Services["directory"]
	dports := flatten(dir["ports"])
	if !containsExact(dports, "127.0.0.1:3389:3389") || !containsExact(dports, "127.0.0.1:3636:3636") {
		t.Fatalf("directory host ports must be loopback: %v", dports)
	}
}

func TestDockerfileAndIgnoreExcludeFixtures(t *testing.T) {
	root := repoRoot(t)
	control := read(t, filepath.Join(root, "deploy", "docker", "Dockerfile.control"))
	boot := read(t, filepath.Join(root, "deploy", "docker", "Dockerfile.bootstrap"))
	ignore := read(t, filepath.Join(root, ".dockerignore"))
	for _, s := range fixtureSecrets {
		if strings.Contains(control, s) || strings.Contains(boot, s) {
			t.Fatalf("Dockerfile must not contain fixture %q", s)
		}
	}
	for _, want := range []string{"secrets", "config/examples/secrets"} {
		if !strings.Contains(ignore, want) {
			t.Fatalf(".dockerignore must exclude %q", want)
		}
	}
}

func TestLiveControlInspect(t *testing.T) {
	if exec.Command("docker", "image", "inspect", "labldap-control:dev").Run() != nil {
		t.Skip("labldap-control:dev not built")
	}
	hist, err := exec.Command("docker", "history", "--no-trunc", "--format", "{{.CreatedBy}}", "labldap-control:dev").CombinedOutput()
	if err != nil {
		t.Fatalf("docker history: %v\n%s", err, hist)
	}
	text := string(hist)
	for _, s := range fixtureSecrets {
		if strings.Contains(text, s) {
			t.Fatalf("image history contains fixture %q", s)
		}
	}
	for _, s := range []string{"DS_DM_PASSWORD", "docker.sock"} {
		if strings.Contains(text, s) {
			t.Fatalf("image history contains %q", s)
		}
	}

	cfg, err := exec.Command("docker", "image", "inspect", "-f", "{{.Config.User}} {{json .Config.Env}} {{json .Config.Volumes}}", "labldap-control:dev").CombinedOutput()
	if err != nil {
		t.Fatalf("docker inspect: %v\n%s", err, cfg)
	}
	got := string(cfg)
	if !strings.Contains(got, "65532") {
		t.Fatalf("control image user missing 65532: %s", got)
	}
	for _, s := range fixtureSecrets {
		if strings.Contains(got, s) {
			t.Fatalf("image config contains fixture %q", s)
		}
	}
}

func controlMentions(compose, token string) bool {
	idx := strings.Index(compose, "\n  control:")
	if idx < 0 {
		return strings.Contains(compose, token)
	}
	rest := compose[idx:]
	if next := strings.Index(rest[1:], "\n  "); next > 0 {
		rest = rest[:next+1]
	}
	return strings.Contains(rest, token)
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

func containsExact(got []string, want string) bool {
	for _, s := range got {
		if s == want {
			return true
		}
	}
	return false
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
