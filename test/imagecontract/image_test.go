package imagecontract

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestControlDockerfileHardening(t *testing.T) {
	root := repoRoot(t)
	text := read(t, filepath.Join(root, "deploy", "docker", "Dockerfile.control"))

	goPin := strings.TrimSpace(read(t, filepath.Join(root, "deploy", "docker", "golang.digest")))
	nodePin := strings.TrimSpace(read(t, filepath.Join(root, "deploy", "docker", "node.digest")))
	alpinePin := strings.TrimSpace(read(t, filepath.Join(root, "deploy", "docker", "alpine.digest")))
	if !strings.Contains(text, "ARG GO_IMAGE="+goPin) {
		t.Fatalf("Dockerfile.control GO_IMAGE must match golang.digest %s", goPin)
	}
	if !strings.Contains(text, "ARG NODE_IMAGE="+nodePin) {
		t.Fatalf("Dockerfile.control NODE_IMAGE must match node.digest %s", nodePin)
	}
	if !strings.Contains(text, "ARG ALPINE_IMAGE="+alpinePin) {
		t.Fatalf("Dockerfile.control ALPINE_IMAGE must match alpine.digest %s", alpinePin)
	}
	if !strings.Contains(text, "USER 65532:65532") {
		t.Fatal("control image must run as uid 65532")
	}
	if !strings.Contains(text, "ca-certificates") {
		t.Fatal("control image must include CA certificates")
	}
	if !strings.Contains(text, "HEALTHCHECK") || !strings.Contains(text, "/health") {
		t.Fatal("control image must HEALTHCHECK GET /health")
	}
	if strings.Contains(text, "/health/ready") {
		t.Fatal("image HEALTHCHECK must not use /health/ready")
	}
	if !strings.Contains(text, "org.opencontainers.image.title=\"labldap-control\"") {
		t.Fatal("control image must set OCI title label")
	}
	if !strings.Contains(text, "internal/observability.version") {
		t.Fatal("control image must stamp observability.version")
	}
	for _, banned := range []string{
		"DS_DM_PASSWORD",
		"docker.sock",
		"config/examples/secrets",
		"secrets/dm.pw",
		"COPY secrets",
		"COPY test",
	} {
		if strings.Contains(text, banned) {
			t.Fatalf("control Dockerfile must not mention %q", banned)
		}
	}
	if strings.Contains(text, "labldap-control:placeholder") {
		t.Fatal("hardened image is labldap-control:dev, not placeholder")
	}
	if !strings.Contains(text, `CMD ["serve", "--help"]`) {
		t.Fatal("default CMD must be serve --help, not --placeholder")
	}
}

func TestBootstrapDockerfilePinsAndVersion(t *testing.T) {
	root := repoRoot(t)
	text := read(t, filepath.Join(root, "deploy", "docker", "Dockerfile.bootstrap"))
	dirsrv := strings.TrimSpace(read(t, filepath.Join(root, "deploy", "docker", "dirsrv.digest")))
	goPin := strings.TrimSpace(read(t, filepath.Join(root, "deploy", "docker", "golang.digest")))
	if !strings.Contains(dirsrv, "@sha256:") {
		t.Fatalf("dirsrv.digest is not a digest pin: %s", dirsrv)
	}
	if !strings.Contains(text, "ARG DIRSRV_IMAGE="+dirsrv) {
		t.Fatalf("Dockerfile.bootstrap DIRSRV_IMAGE must match dirsrv.digest %s", dirsrv)
	}
	if !strings.Contains(text, "ARG GO_IMAGE="+goPin) {
		t.Fatalf("Dockerfile.bootstrap GO_IMAGE must match golang.digest %s", goPin)
	}
	if !strings.Contains(text, "internal/observability.version") {
		t.Fatal("bootstrap image must stamp the same version package as control")
	}
	if !strings.Contains(text, "org.opencontainers.image.title=\"labldap-bootstrap\"") {
		t.Fatal("bootstrap image must set OCI title label")
	}
	if strings.Contains(text, "DS_DM_PASSWORD") || strings.Contains(text, "COPY secrets") {
		t.Fatal("bootstrap Dockerfile must not bake secrets")
	}
}

func TestDockerignoreExcludesSecretsAndSourceCaches(t *testing.T) {
	root := repoRoot(t)
	text := read(t, filepath.Join(root, ".dockerignore"))
	for _, want := range []string{"secrets", "config/examples/secrets", "test", "frontend/node_modules", ".git"} {
		if !strings.Contains(text, want) {
			t.Fatalf(".dockerignore must exclude %q", want)
		}
	}
}

func TestMakefileImageIsReal(t *testing.T) {
	root := repoRoot(t)
	text := read(t, filepath.Join(root, "Makefile"))
	if strings.Contains(text, "PENDING:control-image") {
		t.Fatal("make image must no longer be a pending gate")
	}
	if !strings.Contains(text, "Dockerfile.control") || !strings.Contains(text, "labldap-control:dev") {
		t.Fatal("make image must build labldap-control:dev from Dockerfile.control")
	}
	if !strings.Contains(text, "observability.version") {
		t.Fatal("make image-bootstrap/image must pass matching version ldflags")
	}
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
