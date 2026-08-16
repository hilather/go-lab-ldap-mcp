package imagecontract

import (
	"path/filepath"
	"strings"
	"testing"
)

// T-145: native labldapd image and compose-native profile, statically
// enforced (the live bring-up is gated on T-143/T-144/T-146).
func TestLabldapdDockerfileHardening(t *testing.T) {
	root := repoRoot(t)
	text := read(t, filepath.Join(root, "deploy", "docker", "Dockerfile.labldapd"))

	goPin := strings.TrimSpace(read(t, filepath.Join(root, "deploy", "docker", "golang.digest")))
	basePin := strings.TrimSpace(read(t, filepath.Join(root, "deploy", "docker", "labldapd.digest")))
	if !strings.Contains(basePin, "@sha256:") {
		t.Fatalf("labldapd.digest is not a digest pin: %s", basePin)
	}
	if !strings.Contains(text, "ARG GO_IMAGE="+goPin) {
		t.Fatalf("Dockerfile.labldapd GO_IMAGE must match golang.digest %s", goPin)
	}
	if !strings.Contains(text, "ARG ALPINE_IMAGE="+basePin) {
		t.Fatalf("Dockerfile.labldapd ALPINE_IMAGE must match labldapd.digest %s", basePin)
	}
	if !strings.Contains(text, "./cmd/labldapd") {
		t.Fatal("labldapd image must build ./cmd/labldapd")
	}
	if !strings.Contains(text, "USER 65532:65532") {
		t.Fatal("labldapd image must run as uid 65532")
	}
	if !strings.Contains(text, "ca-certificates") {
		t.Fatal("labldapd image must include CA certificates")
	}
	if !strings.Contains(text, "HEALTHCHECK") || !strings.Contains(text, "127.0.0.1:8389/health") {
		t.Fatal("labldapd image must HEALTHCHECK the loopback health listener")
	}
	if !strings.Contains(text, "EXPOSE 3389 3636 8389") {
		t.Fatal("labldapd image must EXPOSE 3389/3636 and the health port")
	}
	if !strings.Contains(text, `org.opencontainers.image.title="labldapd"`) {
		t.Fatal("labldapd image must set OCI title label")
	}
	if !strings.Contains(text, "internal/observability.version") {
		t.Fatal("labldapd image must stamp observability.version like control/bootstrap")
	}
	if !strings.Contains(text, `CMD ["serve", "--help"]`) {
		t.Fatal("default CMD must be serve --help")
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
			t.Fatalf("labldapd Dockerfile must not mention %q", banned)
		}
	}
}

func TestComposeNativeOverlay(t *testing.T) {
	root := repoRoot(t)
	// Native is the default compose.yaml; compose.native.yaml remains a
	// one-release alias overlay.
	base := read(t, filepath.Join(root, "deploy", "compose", "compose.yaml"))
	if strings.Contains(base, "labldap-control:placeholder") {
		t.Fatal("default compose must not use the placeholder control image")
	}
	if !strings.Contains(base, "image: labldapd:dev") {
		t.Fatal("default compose must run labldapd:dev as the directory engine")
	}
	text := read(t, filepath.Join(root, "deploy", "compose", "compose.native.yaml"))
	if !strings.Contains(text, "alias") && !strings.Contains(text, "image: labldapd:dev") {
		t.Fatal("compose.native.yaml must remain a documented alias or native overlay")
	}
	for _, banned := range []string{"docker.sock", "ca.key", "DS_DM_PASSWORD", "dsconf", "--dsconf-instance"} {
		if strings.Contains(text, banned) {
			t.Fatalf("native overlay must not mention %q (native engine: no dsconf/LDAPI, secrets via files)", banned)
		}
	}
	if !strings.Contains(text, "--directory-manager-password-file") {
		t.Fatal("native directory and bootstrap must pass the DM secret by file")
	}
	if strings.Contains(text, "--directory-manager-password ") {
		t.Fatal("DM password must not appear on argv")
	}
	if !strings.Contains(text, "native-secret-prep") || !strings.Contains(text, "directory-secrets") {
		t.Fatal("native overlay must stage DM/TLS files through native-secret-prep into directory-secrets")
	}
	if !strings.Contains(text, "read_only: true") || !strings.Contains(text, "no-new-privileges:true") {
		t.Fatal("native directory must keep control-grade hardening (read-only root, no-new-privileges)")
	}
	if !strings.Contains(text, "127.0.0.1:8389/health") {
		t.Fatal("native directory healthcheck must hit the loopback health listener")
	}
	if !strings.Contains(text, "uid=65532") && !strings.Contains(text, "65532:65532") {
		t.Fatal("native directory must run as uid 65532")
	}

	eph := read(t, filepath.Join(root, "deploy", "compose", "compose.native-ephemeral.yaml"))
	if !strings.Contains(eph, "type: tmpfs") {
		t.Fatal("native ephemeral overlay must use a tmpfs-backed volume")
	}
	if !strings.Contains(eph, "uid=65532") || !strings.Contains(eph, "gid=65532") {
		t.Fatal("native ephemeral tmpfs must set uid/gid 65532 (labldapd)")
	}
	if !strings.Contains(eph, "host swap") && !strings.Contains(eph, "Host swap") {
		t.Fatal("native ephemeral overlay must document the host-swap caveat")
	}

	persist := read(t, filepath.Join(root, "deploy", "compose", "compose.native-persistent.yaml"))
	if strings.Contains(persist, "tmpfs") {
		t.Fatal("native persistent overlay must not use tmpfs")
	}
	if !strings.Contains(persist, "directory-data") {
		t.Fatal("native persistent overlay must keep the named volume")
	}
	if !strings.Contains(strings.ToLower(persist), "not exposed") {
		t.Fatal("native persistent overlay must document that volume removal is not an API")
	}

	scenario := read(t, filepath.Join(root, "deploy", "compose", "scenario.native.yaml"))
	if !strings.Contains(scenario, "engine: native") {
		t.Fatal("native scenario must select engine: native")
	}
	if !strings.Contains(scenario, "storageMode: ephemeral") {
		t.Fatal("default native scenario must be ephemeral")
	}
	pscenario := read(t, filepath.Join(root, "deploy", "compose", "scenario.native-persistent.yaml"))
	if !strings.Contains(pscenario, "engine: native") || !strings.Contains(pscenario, "storageMode: persistent") {
		t.Fatal("persistent native scenario must set engine: native and storageMode: persistent")
	}
}

func TestMakefileNativeTargetsAreReal(t *testing.T) {
	root := repoRoot(t)
	text := read(t, filepath.Join(root, "Makefile"))
	for _, target := range []string{"image-native:", "compose-up-native:", "compose-down-native:", "compose-reset-native:"} {
		if !strings.Contains(text, "\n"+target) {
			t.Fatalf("Makefile must define %s", target)
		}
	}
	if !strings.Contains(text, "Dockerfile.labldapd") || !strings.Contains(text, "labldapd:dev") {
		t.Fatal("make image-native must build labldapd:dev from Dockerfile.labldapd")
	}
	if !strings.Contains(text, "compose-up-native:") {
		t.Fatal("make compose-up-native must remain as a one-release alias")
	}
	if !strings.Contains(text, "compose-up-389ds:") {
		t.Fatal("make compose-up-389ds must exist for 389 rollback")
	}
	if !strings.Contains(text, "compose.389ds.yaml") {
		t.Fatal("389 rollback must stack compose.389ds.yaml")
	}
	if !strings.Contains(text, "labldapd.digest") {
		t.Fatal("make image-native must pin the labldapd base from labldapd.digest")
	}
}
