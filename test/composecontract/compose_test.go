package composecontract

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

func TestReleaseComposeTopology(t *testing.T) {
	root := repoRoot(t)
	raw := read(t, filepath.Join(root, "deploy", "compose", "compose.yaml"))
	text := string(raw)
	if strings.Contains(text, "labldap-control:placeholder") {
		t.Fatal("T-110+ must use labldap-control:dev, not the T-042 placeholder")
	}
	if strings.Contains(text, "docker.sock") {
		t.Fatal("compose must not mount the Docker socket")
	}
	if strings.Contains(text, "ca.key") {
		t.Fatal("compose must not mount the private CA key")
	}

	var doc struct {
		Services map[string]map[string]any `yaml:"services"`
		Volumes  map[string]any            `yaml:"volumes"`
		Networks map[string]any            `yaml:"networks"`
	}
	if err := yaml.Unmarshal(raw, &doc); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"directory", "bootstrap", "control", "native-secret-prep"} {
		if _, ok := doc.Services[name]; !ok {
			t.Fatalf("missing service %s", name)
		}
	}
	if _, ok := doc.Networks["lab"]; !ok {
		t.Fatal("missing lab network")
	}
	if _, ok := doc.Volumes["directory-data"]; !ok {
		t.Fatal("missing directory-data volume")
	}

	dir := doc.Services["directory"]
	if img, _ := dir["image"].(string); img != "labldapd:dev" {
		t.Fatalf("directory image %q, want labldapd:dev (native default)", img)
	}
	if _, ok := dir["env_file"]; ok {
		t.Fatal("native directory must not take the 389 env_file")
	}
	if env, _ := dir["environment"].(map[string]any); env != nil {
		if _, ok := env["DS_DM_PASSWORD"]; ok {
			t.Fatal("directory must not inline DS_DM_PASSWORD")
		}
	}
	ports := flatten(dir["ports"])
	if !containsExact(ports, "127.0.0.1:3389:3389") || !containsExact(ports, "127.0.0.1:3636:3636") {
		t.Fatalf("directory host ports must be loopback: %v", ports)
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
	if img, _ := ctl["image"].(string); img != "labldap-control:dev" {
		t.Fatalf("control image = %q", img)
	}
	assertDepends(t, ctl, "bootstrap", "service_completed_successfully")
	if ctl["read_only"] != true {
		t.Fatal("control must be read_only")
	}
	if ctl["user"] != "65532:65532" {
		t.Fatalf("control user = %v", ctl["user"])
	}
	caps := flatten(ctl["cap_drop"])
	if !containsExact(caps, "ALL") {
		t.Fatalf("control cap_drop = %v", caps)
	}
	sec := flatten(ctl["security_opt"])
	if !containsExact(sec, "no-new-privileges:true") {
		t.Fatalf("control security_opt = %v", sec)
	}
	tmp := flatten(ctl["tmpfs"])
	if !strings.Contains(strings.Join(tmp, " "), "/tmp") {
		t.Fatalf("control must tmpfs /tmp: %v", tmp)
	}
	env, _ := ctl["environment"].(map[string]any)
	if _, ok := env["DS_DM_PASSWORD"]; ok {
		t.Fatal("control must not receive DS_DM_PASSWORD")
	}
	ports = flatten(ctl["ports"])
	if !containsExact(ports, "127.0.0.1:8443:8443") {
		t.Fatalf("control host publish must be 127.0.0.1:8443:8443, got %v", ports)
	}
	hc, _ := ctl["healthcheck"].(map[string]any)
	test := flatten(hc["test"])
	if !strings.Contains(strings.Join(test, " "), "/health") || strings.Contains(strings.Join(test, " "), "/health/ready") {
		t.Fatalf("control healthcheck must be GET /health only: %v", test)
	}
	vols := flatten(ctl["volumes"])
	for _, v := range vols {
		if strings.Contains(v, "dm.pw") || strings.Contains(v, "directory.env") || strings.Contains(v, "ca.key") {
			t.Fatalf("control must not mount DM or CA key: %s", v)
		}
		if strings.Contains(v, "docker.sock") {
			t.Fatal("control must not mount docker.sock")
		}
		if strings.Contains(v, "token-admin") || strings.Contains(v, "runtime-ldap") {
			t.Fatalf("control must use Compose secrets, not bind-mount %s", v)
		}
	}
	if !strings.Contains(strings.Join(vols, " "), "control-secrets:/run/secrets") {
		t.Fatalf("control must mount the prepared secret volume, got %v", vols)
	}
	if _, ok := doc.Services["secret-prep"]; !ok {
		t.Fatal("missing secret-prep service")
	}
	if _, ok := doc.Volumes["control-secrets"]; !ok {
		t.Fatal("missing control-secrets volume")
	}
}

func TestEphemeralTmpfsVolumeOptions(t *testing.T) {
	root := repoRoot(t)
	raw := read(t, filepath.Join(root, "deploy", "compose", "compose.ephemeral.yaml"))
	text := string(raw)
	if !strings.Contains(text, "type: tmpfs") {
		t.Fatal("ephemeral overlay must use a tmpfs-backed volume")
	}
	if !strings.Contains(text, "uid=65532") || !strings.Contains(text, "gid=65532") {
		t.Fatal("tmpfs must set uid/gid 65532 (labldapd)")
	}
	if !strings.Contains(text, "mode=0750") {
		t.Fatal("tmpfs must set mode=0750")
	}
	if !strings.Contains(text, "size=268435456") {
		t.Fatal("native ephemeral tmpfs must set a 256Mi size")
	}
	if !strings.Contains(text, "host swap") && !strings.Contains(text, "Host swap") {
		t.Fatal("ephemeral overlay must document the host-swap caveat")
	}
}

func TestReleaseCompose389DSTopology(t *testing.T) {
	root := repoRoot(t)
	raw := read(t, filepath.Join(root, "deploy", "compose", "compose.389ds.yaml"))
	text := string(raw)
	if strings.Contains(text, "docker.sock") {
		t.Fatal("389 compose must not mount the Docker socket")
	}
	pin := strings.TrimSpace(string(read(t, filepath.Join(root, "deploy", "docker", "dirsrv.digest"))))
	if !strings.Contains(pin, "@sha256:") {
		t.Fatalf("dirsrv.digest is not a digest pin: %s", pin)
	}
	if !strings.Contains(text, pin) {
		t.Fatal("389 compose must pin the dirsrv digest")
	}
	if !strings.Contains(text, "env_file") {
		t.Fatal("389 directory must use env_file (KD-R20)")
	}
	eph := string(read(t, filepath.Join(root, "deploy", "compose", "compose.389ds-ephemeral.yaml")))
	if !strings.Contains(eph, "uid=389") || !strings.Contains(eph, "size=2147483648") {
		t.Fatal("389 ephemeral tmpfs must stay 2GiB uid 389")
	}
	scenario := string(read(t, filepath.Join(root, "deploy", "compose", "scenario.389ds.yaml")))
	if !strings.Contains(scenario, "engine: 389ds") {
		t.Fatal("389 scenario must select engine: 389ds")
	}
}

func TestPersistentVolumeOverride(t *testing.T) {
	root := repoRoot(t)
	raw := read(t, filepath.Join(root, "deploy", "compose", "compose.persistent.yaml"))
	text := string(raw)
	if strings.Contains(text, "tmpfs") {
		t.Fatal("persistent overlay must not use tmpfs")
	}
	if !strings.Contains(text, "directory-data") {
		t.Fatal("persistent overlay must keep the named volume")
	}
	if !strings.Contains(text, "not exposed") && !strings.Contains(strings.ToLower(text), "not exposed") {
		t.Fatal("persistent overlay must document that volume removal is not an API")
	}
}

func TestComposeScenarioListensAllInterfaces(t *testing.T) {
	root := repoRoot(t)
	text := string(read(t, filepath.Join(root, "deploy", "compose", "scenario.yaml")))
	if !strings.Contains(text, `listen: "0.0.0.0:8443"`) {
		t.Fatal("compose scenario must listen on 0.0.0.0 inside the container")
	}
	if !strings.Contains(text, "engine: native") {
		t.Fatal("default scenario must select engine: native")
	}
	if !strings.Contains(text, "storageMode: ephemeral") {
		t.Fatal("default scenario must be ephemeral")
	}
	if !strings.Contains(text, "/run/secrets/runtime-ldap") || !strings.Contains(text, "/run/secrets/token-admin") {
		t.Fatal("compose scenario must use container secret paths")
	}
	persist := string(read(t, filepath.Join(root, "deploy", "compose", "scenario.persistent.yaml")))
	if !strings.Contains(persist, "storageMode: persistent") {
		t.Fatal("persistent scenario must set storageMode: persistent")
	}
}

func TestMakefileComposeResetIsReal(t *testing.T) {
	root := repoRoot(t)
	text := string(read(t, filepath.Join(root, "Makefile")))
	if strings.Contains(text, "PENDING:compose-reset") {
		t.Fatal("make compose-reset must no longer be pending")
	}
	if !strings.Contains(text, "down --remove-orphans -v") {
		t.Fatal("compose-reset must remove volumes (operator hard reset)")
	}
	if !strings.Contains(text, "tools/setupsecrets") || !strings.Contains(text, "tools/setuptls") {
		t.Fatal("compose-up must use the secret and TLS helpers")
	}
	if !strings.Contains(text, "compose-up-389ds:") || !strings.Contains(text, "instance-ca.crt") {
		t.Fatal("389 rollback compose-up-389ds must publish instance-ca.crt")
	}
	if !strings.Contains(text, "compose.389ds.yaml") {
		t.Fatal("389 rollback must use compose.389ds.yaml")
	}
	if !strings.Contains(text, "scenario.persistent.yaml") {
		t.Fatal("persistent compose-up must use scenario.persistent.yaml")
	}
	if !strings.Contains(text, "--force-recreate secret-prep") {
		t.Fatal("compose-up must force-recreate secret-prep so rotated secrets reach control")
	}
}

func TestOpenAPIHasNoHardReset(t *testing.T) {
	root := repoRoot(t)
	text := string(read(t, filepath.Join(root, "api", "openapi.yaml")))
	for _, banned := range []string{"compose-reset", "volume-remove", "/hard-reset", "docker.sock"} {
		if strings.Contains(text, banned) {
			t.Fatalf("OpenAPI must not expose %q", banned)
		}
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

func containsExact(got []string, want string) bool {
	for _, s := range got {
		if s == want {
			return true
		}
	}
	return false
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

func read(t *testing.T, path string) []byte {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return b
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
