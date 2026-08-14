//go:build integration

package compose

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func TestComposeControlStartsAfterBootstrap(t *testing.T) {
	root := requireCompose(t)
	proj := composeProject(t, "ok")
	dir := t.TempDir()
	envFile, dmFile := writeSecrets(t, dir)
	t.Cleanup(func() { compose(t, root, proj, envFile, dmFile, "down", "--remove-orphans", "-v") })

	compose(t, root, proj, envFile, dmFile, "up", "-d", "--wait", "--remove-orphans")

	out := composeOutput(t, root, proj, envFile, dmFile, "ps", "--format", "{{.Service}} {{.Status}}")
	if !strings.Contains(out, "control") || !strings.Contains(strings.ToLower(out), "healthy") {
		t.Fatalf("control not healthy:\n%s", out)
	}
	health := execOutput(t, "docker", "compose", "-f", filepath.Join(root, "deploy/compose/compose.yaml"),
		"-p", proj, "exec", "-T", "control", "wget", "-q", "-O", "-", "http://127.0.0.1:8443/health")
	if !strings.Contains(health, "ok") {
		t.Fatalf("GET /health = %q", health)
	}
	ready := execCombined(t, "docker", "compose", "-f", filepath.Join(root, "deploy/compose/compose.yaml"),
		"-p", proj, "exec", "-T", "control", "wget", "-q", "-S", "-O", "-", "http://127.0.0.1:8443/health/ready")
	if !strings.Contains(ready, "503") {
		t.Fatalf("GET /health/ready should be 503:\n%s", ready)
	}
	inspect := execOutput(t, "docker", "compose", "-f", filepath.Join(root, "deploy/compose/compose.yaml"),
		"-p", proj, "exec", "-T", "control", "sh", "-c", "env")
	if strings.Contains(inspect, "DS_DM_PASSWORD") {
		t.Fatal("control environment contains DS_DM_PASSWORD")
	}
}

func TestComposeBootstrapFailureLeavesControlDown(t *testing.T) {
	root := requireCompose(t)
	proj := composeProject(t, "fail")
	dir := t.TempDir()
	envFile, dmFile := writeSecrets(t, dir)
	t.Cleanup(func() { compose(t, root, proj, envFile, dmFile, "down", "--remove-orphans", "-v") })

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
		t.Fatalf("expected bootstrap failure:\n%s", out)
	}
	ps := execCombined(t, "docker", "compose", "-f", filepath.Join(root, "deploy/compose/compose.yaml"),
		"-p", proj, "ps", "-a", "--format", "{{.Service}} {{.Status}}")
	if strings.Contains(ps, "control") && !strings.Contains(strings.ToLower(ps), "exited") {
		t.Fatalf("control started after bootstrap failure:\n%s", ps)
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
		build := exec.Command("docker", "build",
			"-f", "deploy/docker/Dockerfile.bootstrap",
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

func writeSecrets(t *testing.T, dir string) (envFile, dmFile string) {
	t.Helper()
	pw := "compose-it-" + strings.ReplaceAll(t.Name(), "/", "-")
	envFile = filepath.Join(dir, "directory.env")
	dmFile = filepath.Join(dir, "dm.pw")
	if err := os.WriteFile(envFile, []byte("DS_DM_PASSWORD="+pw+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(dmFile, []byte(pw+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	return envFile, dmFile
}

func compose(t *testing.T, root, proj, envFile, dmFile string, args ...string) {
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
		t.Fatalf("docker compose %s: %v\n%s", strings.Join(args, " "), err, out)
	}
}

func composeOutput(t *testing.T, root, proj, envFile, dmFile string, args ...string) string {
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
		t.Fatalf("docker compose %s: %v\n%s", strings.Join(args, " "), err, out)
	}
	return string(out)
}

func execOutput(t *testing.T, name string, args ...string) string {
	t.Helper()
	out, err := exec.Command(name, args...).CombinedOutput()
	if err != nil {
		t.Fatalf("%s %s: %v\n%s", name, strings.Join(args, " "), err, out)
	}
	return string(out)
}

func execCombined(_ *testing.T, name string, args ...string) string {
	out, _ := exec.Command(name, args...).CombinedOutput()
	return string(out)
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
