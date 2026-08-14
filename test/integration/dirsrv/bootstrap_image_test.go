//go:build integration

package dirsrv

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
)

const bootstrapImage = "labldap-bootstrap:dev"

var (
	bootstrapImgOnce sync.Once
	bootstrapImgErr  error
)

func requireBootstrapImage(t *testing.T) {
	t.Helper()
	requireDocker(t)
	bootstrapImgOnce.Do(func() {
		if exec.Command("docker", "image", "inspect", bootstrapImage).Run() == nil {
			return
		}
		root, err := moduleRoot()
		if err != nil {
			bootstrapImgErr = err
			return
		}
		ref, err := ImageRef()
		if err != nil {
			bootstrapImgErr = err
			return
		}
		cmd := exec.Command("docker", "build",
			"-f", "deploy/docker/Dockerfile.bootstrap",
			"--build-arg", "DIRSRV_IMAGE="+ref,
			"-t", bootstrapImage,
			".")
		cmd.Dir = root
		out, err := cmd.CombinedOutput()
		if err != nil {
			bootstrapImgErr = err
			t.Logf("docker build:\n%s", redactLogs(string(out)))
		}
	})
	if bootstrapImgErr != nil {
		t.Fatalf("labldap-bootstrap:dev: %v", bootstrapImgErr)
	}
}

func TestBootstrapImageHasDSConf(t *testing.T) {
	requireBootstrapImage(t)
	out, err := exec.Command("docker", "run", "--rm", "--entrypoint", "dsconf", bootstrapImage, "--help").CombinedOutput()
	if err != nil {
		t.Fatalf("dsconf: %v\n%s", err, out)
	}
	if !strings.Contains(string(out), "instance") {
		t.Fatalf("dsconf help unexpected:\n%s", out)
	}
	vout, err := exec.Command("docker", "run", "--rm", bootstrapImage, "version").CombinedOutput()
	if err != nil {
		t.Fatalf("version: %v\n%s", err, vout)
	}
	if !strings.Contains(string(vout), "component=labldap-bootstrap") {
		t.Fatalf("version = %s", vout)
	}
}

func TestBootstrapImageApplySeparateDirectory(t *testing.T) {
	requireBootstrapImage(t)
	inst := Start(t)

	root, err := moduleRoot()
	if err != nil {
		t.Fatal(err)
	}
	hostDir := t.TempDir()
	pw := filepath.Join(hostDir, "dm.pw")
	if err := os.WriteFile(pw, []byte(inst.Password().Reveal()+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	vol := dataVolume(t, inst.Name)
	cfg := filepath.Join(root, "test", "fixtures", "config", "valid")
	args := []string{
		"run", "--rm",
		"--network", "container:" + inst.Name,
		"-v", vol + ":/data:ro",
		"-v", cfg + ":/config:ro",
		"-v", pw + ":/run/secrets/dm.pw:ro",
		bootstrapImage,
		"apply",
		"--config", "/config/minimal.yaml",
		"--directory-manager-password-file", "/run/secrets/dm.pw",
		"--ldap-url", "ldaps://127.0.0.1:3636",
		"--directory-host", inst.Hostname(t),
		"--directory-ca-file", "/data/config/ca.crt",
		"--dsconf-instance", "localhost",
	}
	out, err := exec.Command("docker", args...).CombinedOutput()
	got := redactLogs(string(out), inst.password)
	if err != nil {
		t.Fatalf("bootstrap image apply: %v\n%s", err, got)
	}
	if strings.Contains(got, inst.password) {
		t.Fatal("apply output leaked DM password")
	}
	var sum struct {
		OK bool `json:"ok"`
	}
	if err := decodeSummary(string(out), &sum); err != nil {
		t.Fatalf("summary: %v\n%s", err, got)
	}
	if !sum.OK {
		t.Fatalf("apply not ok:\n%s", got)
	}
}

func dataVolume(t *testing.T, name string) string {
	t.Helper()
	out, err := exec.Command("docker", "inspect", "-f",
		`{{range .Mounts}}{{if eq .Destination "/data"}}{{.Name}}{{end}}{{end}}`,
		name).Output()
	if err != nil {
		t.Fatal(err)
	}
	vol := strings.TrimSpace(string(out))
	if vol == "" {
		t.Fatal("directory container has no /data volume")
	}
	return vol
}
