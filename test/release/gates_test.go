package release

import (
	"fmt"
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
	for _, failure := range []string{"native", "integration", "oracle", "live"} {
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
			// The live smoke is `node tools/live-e2e.mjs`; every other node
			// call succeeds so the other gates reach their own failures.
			write("node", `#!/bin/sh
case "$*" in
*tools/live-e2e.mjs*)
  if [ "$FAIL_GATE" = live ]; then
    printf '%s\n' injected-live-failure
    exit 42
  fi ;;
esac
exit 0
`)
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
			// Prerequisites of test-e2e-live (and theirs) are stubbed too, so
			// no real image recipe runs against the docker stub.
			shim := write("stub.mk", "format lint generate generate-drift test-unit test-security sbom checksums archcheck test-fuzz-short test-native-soak test-diff test-e2e test-integration-native frontend-install frontend-build image image-bootstrap image-native image-pair-check:\n\t@true\n")
			// LIVE_E2E_PREREQS= reaches the test-e2e-live sub-make (command-line
			// variables propagate; the -f shim does not).
			cmd := exec.CommandContext(t.Context(), "make", "-f", filepath.Join(root, "Makefile"), "-f", shim, "verify", "GO="+goStub, "LIVE_E2E_PREREQS=")
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

// test-diff must not report success without the 389 oracle when it is
// required, and must not pull images on developer machines by default.
func TestDiffOracleCannotSoftSkip(t *testing.T) {
	root := repoRoot(t)
	cases := []struct {
		name          string
		docker        string // docker stub body; "" means no docker on PATH
		require       bool
		wantFail      bool
		wantOracle    bool
		wantOutputHas string
	}{
		{name: "required/pull-fails", docker: "info) exit 0 ;;\nimage) exit 1 ;;\npull) exit 1 ;;", require: true, wantFail: true, wantOutputHas: "could not be pulled"},
		{name: "required/pull-succeeds", docker: "info) exit 0 ;;\nimage) exit 1 ;;\npull) exit 0 ;;", require: true, wantOracle: true},
		{name: "required/no-daemon", docker: "info) exit 1 ;;", require: true, wantFail: true, wantOutputHas: "docker is unavailable"},
		{name: "required/no-docker", docker: "", require: true, wantFail: true, wantOutputHas: "docker is unavailable"},
		{name: "optional/no-image", docker: "info) exit 0 ;;\nimage) exit 1 ;;\npull) echo unexpected-pull; exit 1 ;;", wantOutputHas: "oracle leg skipped"},
		{name: "optional/no-daemon", docker: "info) exit 1 ;;", wantOutputHas: "oracle leg skipped"},
		{name: "optional/image-present", docker: "info) exit 0 ;;\nimage) exit 0 ;;", wantOracle: true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			goStub := filepath.Join(dir, "go")
			if err := os.WriteFile(goStub, []byte("#!/bin/sh\nprintf 'go-argv:%s|%s\\n' \"$LABLDAP_DIFF_389\" \"$*\"\n"), 0700); err != nil {
				t.Fatal(err)
			}
			if tc.docker != "" {
				body := "#!/bin/sh\ncase \"$1\" in\n" + tc.docker + "\n*) exit 0 ;;\nesac\n"
				if err := os.WriteFile(filepath.Join(dir, "docker"), []byte(body), 0700); err != nil {
					t.Fatal(err)
				}
			}
			// PATH holds only the stub dir plus the system tool dirs that make
			// and sh need; a real docker elsewhere on PATH must not be found.
			path := dir + ":/usr/bin:/bin"
			if tc.docker == "" {
				if _, err := os.Stat("/usr/bin/docker"); err == nil {
					t.Skip("host has /usr/bin/docker; cannot simulate a docker-less PATH")
				}
			}
			cmd := exec.CommandContext(t.Context(), "make", "test-diff", "GO="+goStub, "DIRSRV_IMAGE=example.invalid/dirsrv@sha256:0")
			cmd.Dir = root
			for _, env := range os.Environ() {
				if !strings.HasPrefix(env, "PATH=") && !strings.HasPrefix(env, "LABLDAP_REQUIRE_389=") &&
					!strings.HasPrefix(env, "MAKEFLAGS=") && !strings.HasPrefix(env, "MFLAGS=") {
					cmd.Env = append(cmd.Env, env)
				}
			}
			cmd.Env = append(cmd.Env, "PATH="+path)
			if tc.require {
				cmd.Env = append(cmd.Env, "LABLDAP_REQUIRE_389=1")
			}
			out, err := cmd.CombinedOutput()
			if (err != nil) != tc.wantFail {
				t.Fatalf("make test-diff err=%v, want failure=%v:\n%s", err, tc.wantFail, out)
			}
			ranOracle := strings.Contains(string(out), "go-argv:1|test ./internal/ldapserver/ -run=TestDifferential389Oracle")
			if ranOracle != tc.wantOracle {
				t.Fatalf("oracle ran=%v, want %v:\n%s", ranOracle, tc.wantOracle, out)
			}
			if !strings.Contains(string(out), "-run=TestDifferentialNativeSequence") {
				t.Fatalf("native leg did not run:\n%s", out)
			}
			if tc.wantOutputHas != "" && !strings.Contains(string(out), tc.wantOutputHas) {
				t.Fatalf("output lacks %q:\n%s", tc.wantOutputHas, out)
			}
			if strings.Contains(string(out), "unexpected-pull") {
				t.Fatalf("pulled without LABLDAP_REQUIRE_389:\n%s", out)
			}
		})
	}
}

// The CI integration job runs make test-parity and then make
// test-integration; its job timeout must cover both Go budgets plus setup.
func TestCIIntegrationTimeoutCoversBudget(t *testing.T) {
	root := repoRoot(t)
	mk := strings.Split(read(t, filepath.Join(root, "Makefile")), "\n")
	minutes := func(v string) int {
		t.Helper()
		var n int
		if _, err := fmt.Sscanf(strings.TrimSuffix(v, "m"), "%d", &n); err != nil || !strings.HasSuffix(v, "m") {
			t.Fatalf("unparseable minutes %q", v)
		}
		return n
	}
	parity, integration := -1, -1
	for i, line := range mk {
		if line == "test-parity:" && i+1 < len(mk) {
			f := strings.Fields(mk[i+1])
			for j := range f {
				if f[j] == "-timeout" && j+1 < len(f) {
					parity = minutes(f[j+1])
				}
			}
		}
		if strings.HasPrefix(line, "INTEGRATION_TIMEOUT ?=") {
			integration = minutes(strings.TrimSpace(strings.TrimPrefix(line, "INTEGRATION_TIMEOUT ?=")))
		}
	}
	if parity < 0 || integration < 0 {
		t.Fatalf("could not read budgets: parity=%d integration=%d", parity, integration)
	}
	ci := strings.Split(read(t, filepath.Join(root, ".github/workflows/ci.yml")), "\n")
	job := -1
	in := false
	for _, line := range ci {
		if line == "  integration:" {
			in = true
			continue
		}
		if in && strings.HasPrefix(line, "  ") && !strings.HasPrefix(line, "   ") && strings.TrimSpace(line) != "" {
			break // next job key
		}
		if in && strings.HasPrefix(line, "    timeout-minutes:") {
			fmt.Sscanf(strings.TrimSpace(strings.TrimPrefix(line, "    timeout-minutes:")), "%d", &job)
		}
	}
	if job < 0 {
		t.Fatal("integration job timeout-minutes not found")
	}
	if job < parity+integration+10 {
		t.Fatalf("CI integration timeout %dm < parity %dm + integration %dm + 10m setup", job, parity, integration)
	}
}
