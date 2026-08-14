//go:build integration

package compose

import (
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"
)

func TestComposeControlStartsAfterBootstrap(t *testing.T) {
	root := requireCompose(t)
	proj := composeProject(t, "ok")
	dir := t.TempDir()
	envFile, dmFile, pw := writeSecrets(t, dir)
	t.Cleanup(func() { compose(t, root, proj, envFile, dmFile, pw, "down", "--remove-orphans", "-v") })

	compose(t, root, proj, envFile, dmFile, pw, "up", "-d", "--wait", "--remove-orphans")

	out := composeOutput(t, root, proj, envFile, dmFile, pw, "ps", "--format", "{{.Service}} {{.Status}}")
	if !strings.Contains(out, "control") || !strings.Contains(strings.ToLower(out), "healthy") {
		t.Fatalf("control not healthy:\n%s", redactLogs(out, pw))
	}

	pub := strings.TrimSpace(strings.SplitN(
		composeOutput(t, root, proj, envFile, dmFile, pw, "port", "control", "8443"), "\n", 2)[0])
	if pub == "" {
		t.Fatal("control has no published 8443")
	}
	live, err := httpGet("http://" + pub + "/health")
	if err != nil {
		t.Fatalf("host GET /health via %s: %v", pub, err)
	}
	if live.status != http.StatusOK || !strings.Contains(live.body, "ok") {
		t.Fatalf("host GET /health status=%d body=%q", live.status, live.body)
	}
	ready, err := httpGet("http://" + pub + "/health/ready")
	if err != nil {
		t.Fatalf("host GET /health/ready via %s: %v", pub, err)
	}
	if ready.status != http.StatusServiceUnavailable {
		t.Fatalf("host GET /health/ready status=%d body=%q", ready.status, ready.body)
	}

	inspect := execOutput(t, pw, "docker", "compose", "-f", filepath.Join(root, "deploy/compose/compose.yaml"),
		"-p", proj, "exec", "-T", "control", "sh", "-c", "env")
	if strings.Contains(inspect, "DS_DM_PASSWORD") {
		t.Fatal("control environment contains DS_DM_PASSWORD")
	}
}

func TestComposeBootstrapFailureLeavesControlDown(t *testing.T) {
	root := requireCompose(t)
	proj := composeProject(t, "fail")
	dir := t.TempDir()
	envFile, dmFile, pw := writeSecrets(t, dir)
	t.Cleanup(func() { compose(t, root, proj, envFile, dmFile, pw, "down", "--remove-orphans", "-v") })

	bad := t.TempDir()
	if err := os.WriteFile(filepath.Join(bad, "minimal.yaml"), []byte("not-a-lab-scenario: true\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command("docker", "compose",
		"-f", filepath.Join(root, "deploy/compose/compose.yaml"),
		"-p", proj, "up", "-d", "--wait", "--remove-orphans")
	cmd.Dir = root
	cmd.Env = append(os.Environ(),
		"LABLDAP_DIRECTORY_ENVFILE="+envFile,
		"LABLDAP_DM_PASSWORD_FILE="+dmFile,
		"LABLDAP_SCENARIO_DIR="+bad,
	)
	out, err := cmd.CombinedOutput()
	if err == nil {
		t.Fatalf("expected bootstrap failure:\n%s", redactLogs(string(out), pw))
	}
	ps := execCombined("docker", "compose", "-f", filepath.Join(root, "deploy/compose/compose.yaml"),
		"-p", proj, "ps", "-a", "--format", "{{.Service}} {{.Status}}")
	if controlStarted(ps) {
		t.Fatalf("control started after bootstrap failure:\n%s", redactLogs(ps, pw))
	}
}

func controlStarted(ps string) bool {
	for _, line := range strings.Split(ps, "\n") {
		line = strings.TrimSpace(line)
		if !strings.HasPrefix(line, "control") {
			continue
		}
		low := strings.ToLower(line)
		if strings.Contains(low, "exit") {
			return false
		}
		for _, tok := range []string{"up", "running", "healthy", "restarting"} {
			if strings.Contains(low, tok) {
				return true
			}
		}
		// "Created" is allocated but not started — not ready.
		return false
	}
	return false
}

func TestControlStarted(t *testing.T) {
	cases := []struct {
		in   string
		want bool
	}{
		{"", false},
		{"bootstrap Exited (1)\ndirectory Up", false},
		{"control Created\nbootstrap Exited (1)", false},
		{"control Exited (1)", false},
		{"control Up 3 seconds (healthy)", true},
		{"control Restarting", true},
	}
	for _, tc := range cases {
		if got := controlStarted(tc.in); got != tc.want {
			t.Fatalf("controlStarted(%q)=%v, want %v", tc.in, got, tc.want)
		}
	}
}

func composeProject(t *testing.T, kind string) string {
	t.Helper()
	name := strings.ToLower(strings.NewReplacer("/", "-", "_", "-").Replace(t.Name()))
	return "labldap-it-" + kind + "-" + name
}

func requireCompose(t *testing.T) string {
	t.Helper()
	if _, err := exec.LookPath("docker"); err != nil {
		t.Skip("docker not on PATH")
	}
	if err := exec.Command("docker", "info").Run(); err != nil {
		t.Skip("docker daemon not available")
	}
	if err := exec.Command("docker", "compose", "version").Run(); err != nil {
		t.Skip("docker compose not available")
	}
	root, err := moduleRoot()
	if err != nil {
		t.Fatal(err)
	}
	if exec.Command("docker", "image", "inspect", "labldap-bootstrap:dev").Run() != nil {
		ref, err := os.ReadFile(filepath.Join(root, "deploy", "docker", "dirsrv.digest"))
		if err != nil {
			t.Fatal(err)
		}
		build := exec.Command("docker", "build",
			"-f", "deploy/docker/Dockerfile.bootstrap",
			"--build-arg", "DIRSRV_IMAGE="+strings.TrimSpace(string(ref)),
			"-t", "labldap-bootstrap:dev", ".")
		build.Dir = root
		if out, err := build.CombinedOutput(); err != nil {
			t.Fatalf("image-bootstrap: %v\n%s", err, out)
		}
	}
	if exec.Command("docker", "image", "inspect", "labldap-control:placeholder").Run() != nil {
		build := exec.Command("docker", "build",
			"-f", "deploy/docker/Dockerfile.control-placeholder",
			"-t", "labldap-control:placeholder", ".")
		build.Dir = root
		if out, err := build.CombinedOutput(); err != nil {
			t.Fatalf("control placeholder: %v\n%s", err, out)
		}
	}
	return root
}

func writeSecrets(t *testing.T, dir string) (envFile, dmFile, pw string) {
	t.Helper()
	pw = "compose-it-" + strings.ReplaceAll(t.Name(), "/", "-")
	envFile = filepath.Join(dir, "directory.env")
	dmFile = filepath.Join(dir, "dm.pw")
	if err := os.WriteFile(envFile, []byte("DS_DM_PASSWORD="+pw+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(dmFile, []byte(pw+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	return envFile, dmFile, pw
}

func compose(t *testing.T, root, proj, envFile, dmFile, pw string, args ...string) {
	t.Helper()
	cmd := exec.Command("docker", append([]string{
		"compose", "-f", filepath.Join(root, "deploy/compose/compose.yaml"), "-p", proj,
	}, args...)...)
	cmd.Dir = root
	cmd.Env = append(os.Environ(),
		"LABLDAP_DIRECTORY_ENVFILE="+envFile,
		"LABLDAP_DM_PASSWORD_FILE="+dmFile,
	)
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("docker compose %s: %v\n%s", strings.Join(args, " "), err, redactLogs(string(out), pw))
	}
}

func composeOutput(t *testing.T, root, proj, envFile, dmFile, pw string, args ...string) string {
	t.Helper()
	cmd := exec.Command("docker", append([]string{
		"compose", "-f", filepath.Join(root, "deploy/compose/compose.yaml"), "-p", proj,
	}, args...)...)
	cmd.Dir = root
	cmd.Env = append(os.Environ(),
		"LABLDAP_DIRECTORY_ENVFILE="+envFile,
		"LABLDAP_DM_PASSWORD_FILE="+dmFile,
	)
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("docker compose %s: %v\n%s", strings.Join(args, " "), err, redactLogs(string(out), pw))
	}
	return string(out)
}

func execOutput(t *testing.T, pw, name string, args ...string) string {
	t.Helper()
	out, err := exec.Command(name, args...).CombinedOutput()
	if err != nil {
		t.Fatalf("%s %s: %v\n%s", name, strings.Join(args, " "), err, redactLogs(string(out), pw))
	}
	return string(out)
}

func execCombined(name string, args ...string) string {
	out, _ := exec.Command(name, args...).CombinedOutput()
	return string(out)
}

type httpResult struct {
	status int
	body   string
}

func httpGet(url string) (httpResult, error) {
	client := &http.Client{Timeout: 3 * time.Second}
	resp, err := client.Get(url)
	if err != nil {
		return httpResult{}, err
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	return httpResult{status: resp.StatusCode, body: string(b)}, nil
}

var (
	pemPrivate     = regexp.MustCompile(`-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----[\s\S]*?-----END [A-Z0-9 ]*PRIVATE KEY-----`)
	passwordAssign = regexp.MustCompile(`(?i)((?:set )?cn=Directory Manager password to |password set to |Root DN password: |DS_DM_PASSWORD=)("?)([^"\s]+)("?)`)
)

func redactLogs(s string, secrets ...string) string {
	s = pemPrivate.ReplaceAllString(s, "[redacted-pem]")
	s = passwordAssign.ReplaceAllString(s, "${1}${2}[redacted]${4}")
	for _, sec := range secrets {
		if sec != "" {
			s = strings.ReplaceAll(s, sec, "[redacted]")
		}
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
			return "", os.ErrNotExist
		}
		dir = parent
	}
}
