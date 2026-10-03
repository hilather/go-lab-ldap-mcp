package release

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// Exercise make with successful prerequisite stubs and failing engine commands.
// This catches shell recipes that print a warning or overwrite the failure status.
func TestVerifyPropagatesEngineFailures(t *testing.T) {
	root := repoRoot(t)
	for _, failure := range []string{"native", "integration", "oracle"} {
		t.Run(failure, func(t *testing.T) {
			dir := t.TempDir()
			write := func(name, body string) string {
				path := filepath.Join(dir, name)
				if err := os.WriteFile(path, []byte(body), 0700); err != nil {
					t.Fatal(err)
				}
				return path
			}
			write("docker", "#!/bin/sh\nexit 0\n")
			goStub := write("go", `#!/bin/sh
case "$*" in
*'-tags=integration ./test/parity/'*) gate=oracle ;;
*'-tags=integration ./test/integration/'*) gate=integration ;;
*'./test/parity/'*) gate=native ;;
*) exit 0 ;;
esac
if [ "$FAIL_GATE" = "$gate" ]; then
  printf '%s\n' "injected-$gate-failure"
  exit 42
fi
exit 0
`)
			shim := write("stub.mk", "format lint generate generate-drift test-unit test-security sbom checksums archcheck test-fuzz-short test-native-soak test-diff test-e2e test-integration-native frontend-install frontend-build:\n\t@true\n")
			cmd := exec.CommandContext(t.Context(), "make", "-f", filepath.Join(root, "Makefile"), "-f", shim, "verify", "GO="+goStub)
			cmd.Dir = root
			cmd.Env = append(os.Environ(), "PATH="+dir+":"+os.Getenv("PATH"), "FAIL_GATE="+failure)
			out, err := cmd.CombinedOutput()
			if !strings.Contains(string(out), "injected-"+failure+"-failure") {
				t.Fatalf("intended %s failure was not exercised:\n%s", failure, out)
			}
			if err == nil {
				t.Fatalf("verify swallowed %s failure:\n%s", failure, out)
			}
			if strings.Contains(string(out), "verify: ok") {
				t.Fatalf("false success after %s failure:\n%s", failure, out)
			}
		})
	}
}

func TestUnitGateIncludesParity(t *testing.T) {
	mk := read(t, filepath.Join(repoRoot(t), "Makefile"))
	if strings.Contains(mk, "grep -v '/test/parity'") {
		t.Fatal("unit gate excludes parity")
	}
}

func TestImagePairRebuildsStaleBootstrapBeforeComparing(t *testing.T) {
	root := repoRoot(t)
	for _, parallel := range []string{"1", "2"} {
		t.Run("jobs-"+parallel, func(t *testing.T) {
			dir := t.TempDir()
			// A pre-existing bootstrap has the old version until its actual build runs.
			docker := `#!/bin/sh
case "$*" in
build*Dockerfile.bootstrap*) touch "$IMAGE_TEST_STATE/bootstrap" ;;
build*Dockerfile.control*) touch "$IMAGE_TEST_STATE/control" ;;
*'labldap-bootstrap:dev version'*)
  if [ -f "$IMAGE_TEST_STATE/bootstrap" ]; then echo 'version=candidate'; else echo 'version=old'; fi ;;
*'labldap-control:dev version'*) echo 'version=candidate' ;;
run*-d*) echo fake-container ;;
*) exit 0 ;;
esac
`
			if err := os.WriteFile(filepath.Join(dir, "docker"), []byte(docker), 0700); err != nil {
				t.Fatal(err)
			}
			cmd := exec.CommandContext(t.Context(), "make", "-j"+parallel, "image-pair-check", "VERSION=candidate")
			cmd.Dir = root
			cmd.Env = append(os.Environ(), "PATH="+dir+":"+os.Getenv("PATH"), "IMAGE_TEST_STATE="+dir)
			out, err := cmd.CombinedOutput()
			if err != nil {
				t.Fatalf("stale bootstrap blocked candidate rebuild: %v\n%s", err, out)
			}
			for _, image := range []string{"bootstrap", "control"} {
				if _, err := os.Stat(filepath.Join(dir, image)); err != nil {
					t.Fatalf("%s was not built", image)
				}
			}
		})
	}
}

// Inspect the actual argv sent to Go, without starting any engine. The caller
// must be able to bound a slower oracle run independently of the default.
func TestIntegrationTimeoutBudget(t *testing.T) {
	root := repoRoot(t)
	for _, target := range []string{"test-integration", "test-integration-native"} {
		for _, budget := range []string{"", "52m"} {
			t.Run(target+"/"+budget, func(t *testing.T) {
				dir := t.TempDir()
				stub := filepath.Join(dir, "go")
				if err := os.WriteFile(stub, []byte("#!/bin/sh\nprintf '%s\\n' \"$@\"\n"), 0700); err != nil {
					t.Fatal(err)
				}
				args := []string{target, "GO=" + stub}
				expected := "45m"
				if budget != "" {
					args = append(args, "INTEGRATION_TIMEOUT="+budget)
					expected = budget
				}
				cmd := exec.CommandContext(t.Context(), "make", args...)
				cmd.Dir = root
				// Unset ambient overrides so this really exercises the repository default.
				for _, env := range os.Environ() {
					if !strings.HasPrefix(env, "INTEGRATION_TIMEOUT=") &&
						!strings.HasPrefix(env, "MAKEFLAGS=") &&
						!strings.HasPrefix(env, "MFLAGS=") {
						cmd.Env = append(cmd.Env, env)
					}
				}
				out, err := cmd.CombinedOutput()
				if err != nil {
					t.Fatalf("make failed: %v\n%s", err, out)
				}
				if !strings.Contains(string(out), "\n-timeout\n"+expected+"\n") {
					t.Fatalf("missing explicit timeout %s in Go argv:\n%s", expected, out)
				}
			})
		}
	}
}
