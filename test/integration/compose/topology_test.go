//go:build integration

package compose

import (
	"bytes"
	"crypto/tls"
	"encoding/json"
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
	env := writeLabMaterial(t, root, dir)
	t.Cleanup(func() { compose(t, root, proj, env, false, "down", "--remove-orphans", "-v") })

	upStack(t, root, proj, env, false)

	out := composeOutput(t, root, proj, env, false, "ps", "--format", "{{.Service}} {{.Status}}")
	if !strings.Contains(out, "control") || !strings.Contains(strings.ToLower(out), "healthy") {
		t.Fatalf("control not healthy:\n%s", redactLogs(out, env.secrets...))
	}

	live := hostGet(t, root, proj, env, "/health")
	if live.status != http.StatusOK || !(strings.Contains(live.body, `"live"`) || strings.Contains(live.body, `"status":"live"`)) {
		t.Fatalf("GET /health status=%d body=%q", live.status, live.body)
	}
	ready := hostGet(t, root, proj, env, "/health/ready")
	if ready.status != http.StatusOK {
		t.Fatalf("GET /health/ready status=%d body=%q", ready.status, ready.body)
	}

	bindEnv(&env, root, false)
	cid := strings.TrimSpace(composeOutput(t, root, proj, env, false, "ps", "-q", "control"))
	if cid == "" {
		t.Fatal("control container id missing")
	}
	rawEnv := execOutput(t, env.secrets, "docker", "inspect", "-f", "{{range .Config.Env}}{{println .}}{{end}}", cid)
	if strings.Contains(rawEnv, "DS_DM_PASSWORD") {
		t.Fatal("control environment contains DS_DM_PASSWORD")
	}
	mounts := execOutput(t, env.secrets, "docker", "inspect", "-f", "{{range .Mounts}}{{.Source}} {{.Destination}}\n{{end}}", cid)
	if strings.Contains(mounts, "docker.sock") || strings.Contains(mounts, "ca.key") || strings.Contains(mounts, "dm.pw") {
		t.Fatalf("control mounts include forbidden path:\n%s", mounts)
	}
}

func TestComposeBootstrapFailureLeavesControlDown(t *testing.T) {
	root := requireCompose(t)
	proj := composeProject(t, "fail")
	dir := t.TempDir()
	env := writeLabMaterial(t, root, dir)
	t.Cleanup(func() { compose(t, root, proj, env, false, "down", "--remove-orphans", "-v") })

	bad := t.TempDir()
	if err := os.WriteFile(filepath.Join(bad, "scenario.yaml"), []byte("not-a-lab-scenario: true\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	env.scenario = filepath.Join(bad, "scenario.yaml")
	compose(t, root, proj, env, false, "up", "-d", "--wait", "--remove-orphans", "directory")
	publishCA(t, root, proj, env, false)
	cmd := exec.Command("docker", append(composeArgs(root, proj, env, false), "up", "-d", "--wait", "--remove-orphans")...)
	cmd.Dir = root
	cmd.Env = composeEnv(env)
	out, err := cmd.CombinedOutput()
	if err == nil {
		t.Fatalf("expected bootstrap failure:\n%s", redactLogs(string(out), env.secrets...))
	}
	ps := execCombined(append([]string{"docker"}, append(composeArgs(root, proj, env, false), "ps", "-a", "--format", "{{.Service}} {{.Status}}")...)...)
	if controlStarted(ps) {
		t.Fatalf("control started after bootstrap failure:\n%s", redactLogs(ps, env.secrets...))
	}
}

func TestEphemeralRecreateDropsRuntimeEntry(t *testing.T) {
	root := requireCompose(t)
	proj := composeProject(t, "eph")
	dir := t.TempDir()
	env := writeLabMaterial(t, root, dir)
	t.Cleanup(func() { compose(t, root, proj, env, false, "down", "--remove-orphans", "-v") })
	upStack(t, root, proj, env, false)
	createRuntimeUser(t, root, proj, env)
	if !userExists(t, root, proj, env, "runtime-extra") {
		t.Fatal("expected runtime-extra after create")
	}
	compose(t, root, proj, env, false, "down", "--remove-orphans")
	upStack(t, root, proj, env, false)
	if userExists(t, root, proj, env, "runtime-extra") {
		t.Fatal("ephemeral recreate must drop runtime entries")
	}
	if !userExists(t, root, proj, env, "alice") {
		t.Fatal("baseline alice must be reapplied")
	}
}

func TestPersistentRestartKeepsRuntimeEntry(t *testing.T) {
	root := requireCompose(t)
	proj := composeProject(t, "per")
	dir := t.TempDir()
	env := writeLabMaterial(t, root, dir)
	t.Cleanup(func() { compose(t, root, proj, env, true, "down", "--remove-orphans", "-v") })
	upStack(t, root, proj, env, true)
	createRuntimeUser(t, root, proj, env)
	compose(t, root, proj, env, true, "restart", "directory")
	// Directory restart can drop published ports; wait for health then control.
	compose(t, root, proj, env, true, "up", "-d", "--wait", "directory")
	waitControl(t, root, proj, env, true)
	if !userExists(t, root, proj, env, "runtime-extra") {
		t.Fatal("persistent restart must keep runtime entries")
	}
	rev := baselineRevision(t, root, proj, env)
	reset := hostJSON(t, root, proj, env, http.MethodPost, "/api/v1/reset", map[string]string{
		"name": "compose-lab", "expectedRevision": rev,
	})
	if reset.status != http.StatusAccepted && reset.status != http.StatusOK {
		t.Fatalf("soft reset status=%d body=%s", reset.status, reset.body)
	}
	deadline := time.Now().Add(2 * time.Minute)
	for time.Now().Before(deadline) {
		if !userExists(t, root, proj, env, "runtime-extra") && userExists(t, root, proj, env, "alice") {
			return
		}
		time.Sleep(time.Second)
	}
	t.Fatal("soft reset must remove runtime-extra and keep baseline alice")
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

func TestComposeEnvPersistentBindings(t *testing.T) {
	root := "/repo"
	env := labEnv{
		envFile:    "/tmp/directory.env",
		dmFile:     "/tmp/dm.pw",
		secretDir:  "/tmp/secrets",
		labCA:      "/tmp/ca.crt",
		instanceCA: "/tmp/instance-ca.crt",
		caFile:     "/tmp/instance-ca.crt",
		scenario:   filepath.Join(root, "deploy", "compose", "scenario.389ds.yaml"),
	}
	bindEnv(&env, root, true)
	got := map[string]string{}
	for _, kv := range composeEnv(env) {
		k, v, ok := strings.Cut(kv, "=")
		if ok {
			got[k] = v
		}
	}
	if got["LABLDAP_TLS_CA"] != env.labCA {
		t.Fatalf("LABLDAP_TLS_CA=%q, want lab CA %q", got["LABLDAP_TLS_CA"], env.labCA)
	}
	wantScenario := filepath.Join(root, "deploy", "compose", "scenario.389ds-persistent.yaml")
	if got["LABLDAP_SCENARIO_FILE"] != wantScenario {
		t.Fatalf("LABLDAP_SCENARIO_FILE=%q, want %q", got["LABLDAP_SCENARIO_FILE"], wantScenario)
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
		return false
	}
	return false
}

type labEnv struct {
	envFile    string
	dmFile     string
	secrets    []string
	secretDir  string
	tlsDir     string
	caFile     string
	labCA      string
	instanceCA string
	scenario   string
	files      []string
	token      string
}

func composeProject(t *testing.T, kind string) string {
	t.Helper()
	name := strings.ToLower(strings.NewReplacer("/", "-", "_", "-").Replace(t.Name()))
	return "labldap-it-" + kind + "-" + name
}

func requireCompose(t *testing.T) string {
	t.Helper()
	// T-148: the native engine run (LABLDAP_IT_ENGINE=native, see
	// test/integration/dirsrv/engine.go) is the hermetic in-process fixture;
	// these tests exercise the 389 Compose overlay only (parity contract
	// D2/D4). Default `make compose-up` is native; 389 is compose-up-389ds.
	if os.Getenv("LABLDAP_IT_ENGINE") == "native" {
		t.Skip("389 compose overlay only under LABLDAP_IT_ENGINE=native (parity contract D2/D4)")
	}
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
	ensureImage(t, root, "labldap-bootstrap:dev", []string{
		"build", "-f", "deploy/docker/Dockerfile.bootstrap",
		"--build-arg", "DIRSRV_IMAGE=" + strings.TrimSpace(readFile(t, filepath.Join(root, "deploy/docker/dirsrv.digest"))),
		"-t", "labldap-bootstrap:dev", ".",
	})
	ensureImage(t, root, "labldap-control:dev", []string{
		"build", "-f", "deploy/docker/Dockerfile.control",
		"-t", "labldap-control:dev", ".",
	})
	return root
}

func ensureImage(t *testing.T, root, tag string, build []string) {
	t.Helper()
	if exec.Command("docker", "image", "inspect", tag).Run() == nil {
		return
	}
	cmd := exec.Command("docker", build...)
	cmd.Dir = root
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("%s: %v\n%s", tag, err, out)
	}
}

func writeLabMaterial(t *testing.T, root, dir string) labEnv {
	t.Helper()
	secretDir := filepath.Join(dir, "secrets")
	tlsDir := filepath.Join(secretDir, "tls")
	runTool(t, root, nil, []string{"run", "./tools/setupsecrets", "--dir", secretDir})
	runTool(t, root, nil, []string{"run", "./tools/setuptls", "generate", "--dir", tlsDir, "--host", "directory"})
	token := strings.TrimSpace(readFile(t, filepath.Join(secretDir, "token-admin")))
	dm := strings.TrimSpace(readFile(t, filepath.Join(secretDir, "dm.pw")))
	return labEnv{
		envFile:    filepath.Join(secretDir, "directory.env"),
		dmFile:     filepath.Join(secretDir, "dm.pw"),
		secrets:    []string{token, dm},
		secretDir:  secretDir,
		tlsDir:     tlsDir,
		labCA:      filepath.Join(tlsDir, "ca.crt"),
		instanceCA: filepath.Join(tlsDir, "instance-ca.crt"),
		caFile:     filepath.Join(tlsDir, "instance-ca.crt"),
		scenario:   filepath.Join(root, "deploy", "compose", "scenario.389ds.yaml"),
		token:      token,
	}
}

func overlayFiles(root string, persistent bool) []string {
	files := []string{filepath.Join(root, "deploy/compose/compose.389ds.yaml")}
	if persistent {
		return append(files, filepath.Join(root, "deploy/compose/compose.389ds-persistent.yaml"))
	}
	return append(files, filepath.Join(root, "deploy/compose/compose.389ds-ephemeral.yaml"))
}

func bindEnv(env *labEnv, root string, persistent bool) {
	env.files = overlayFiles(root, persistent)
	if persistent {
		env.caFile = env.labCA
		if env.scenario == filepath.Join(root, "deploy", "compose", "scenario.389ds.yaml") {
			env.scenario = filepath.Join(root, "deploy", "compose", "scenario.389ds-persistent.yaml")
		}
		return
	}
	env.caFile = env.instanceCA
}

func upStack(t *testing.T, root, proj string, env labEnv, persistent bool) {
	t.Helper()
	bindEnv(&env, root, persistent)
	compose(t, root, proj, env, persistent, "up", "-d", "--wait", "--remove-orphans", "directory")
	if persistent {
		importTLS(t, root, proj, env, persistent)
	} else {
		publishCA(t, root, proj, env, persistent)
	}
	compose(t, root, proj, env, persistent, "up", "-d", "--wait", "--remove-orphans")
	waitControl(t, root, proj, env, persistent)
}

func importTLS(t *testing.T, root, proj string, env labEnv, persistent bool) {
	t.Helper()
	bindEnv(&env, root, persistent)
	args := []string{"run", "./tools/setuptls", "import", "--dir", env.tlsDir, "--project", proj,
		"-f", env.files[0], "-f", env.files[1]}
	runTool(t, root, composeEnv(env), args)
}

func publishCA(t *testing.T, root, proj string, env labEnv, persistent bool) {
	t.Helper()
	bindEnv(&env, root, persistent)
	args := []string{"run", "./tools/setuptls", "publish", "--out", env.instanceCA, "--project", proj,
		"-f", env.files[0], "-f", env.files[1]}
	runTool(t, root, composeEnv(env), args)
}

func waitControl(t *testing.T, root, proj string, env labEnv, persistent bool) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Minute)
	var last string
	for time.Now().Before(deadline) {
		res, err := tryHostGet(root, proj, env, persistent, "/health/ready")
		if err == nil && res.status == http.StatusOK {
			return
		}
		if err != nil {
			last = err.Error()
		} else {
			last = res.body
		}
		time.Sleep(500 * time.Millisecond)
	}
	t.Fatalf("control /health/ready not ready: %s", redactLogs(last, env.secrets...))
}

func composeArgs(root, proj string, env labEnv, persistent bool) []string {
	bindEnv(&env, root, persistent)
	return []string{"compose", "-f", env.files[0], "-f", env.files[1], "-p", proj}
}

func composeEnv(env labEnv) []string {
	return append(os.Environ(),
		"LABLDAP_DIRECTORY_ENVFILE="+env.envFile,
		"LABLDAP_DM_PASSWORD_FILE="+env.dmFile,
		"LABLDAP_SECRETS_DIR="+env.secretDir,
		"LABLDAP_TLS_CA="+env.caFile,
		"LABLDAP_SCENARIO_FILE="+env.scenario,
	)
}

func compose(t *testing.T, root, proj string, env labEnv, persistent bool, args ...string) {
	t.Helper()
	bindEnv(&env, root, persistent)
	cmd := exec.Command("docker", append(composeArgs(root, proj, env, persistent), args...)...)
	cmd.Dir = root
	cmd.Env = composeEnv(env)
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("docker compose %s: %v\n%s", strings.Join(args, " "), err, redactLogs(string(out), env.secrets...))
	}
}

func composeOutput(t *testing.T, root, proj string, env labEnv, persistent bool, args ...string) string {
	t.Helper()
	bindEnv(&env, root, persistent)
	cmd := exec.Command("docker", append(composeArgs(root, proj, env, persistent), args...)...)
	cmd.Dir = root
	cmd.Env = composeEnv(env)
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("docker compose %s: %v\n%s", strings.Join(args, " "), err, redactLogs(string(out), env.secrets...))
	}
	return string(out)
}

func runTool(t *testing.T, root string, env []string, args []string) {
	t.Helper()
	cmd := exec.Command("go", args...)
	cmd.Dir = root
	if env != nil {
		cmd.Env = env
	}
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("go %s: %v\n%s", strings.Join(args, " "), err, out)
	}
}

func hostGet(t *testing.T, root, proj string, env labEnv, path string) httpResult {
	t.Helper()
	res, err := tryHostGet(root, proj, env, false, path)
	if err != nil {
		t.Fatal(err)
	}
	return res
}

func tryHostGet(root, proj string, env labEnv, persistent bool, path string) (httpResult, error) {
	pub := published(root, proj, env, persistent)
	if pub == "" {
		return httpResult{}, errNoPort
	}
	return httpDo(http.MethodGet, "https://"+pub+path, "", nil)
}

func hostJSON(t *testing.T, root, proj string, env labEnv, method, path string, body any) httpResult {
	t.Helper()
	pub := published(root, proj, env, strings.Contains(proj, "-per-") || strings.Contains(proj, "-upg-"))
	raw, _ := json.Marshal(body)
	res, err := httpDo(method, "https://"+pub+path, env.token, raw)
	if err != nil {
		t.Fatal(err)
	}
	return res
}

func published(root, proj string, env labEnv, persistent bool) string {
	bindEnv(&env, root, persistent)
	cmd := exec.Command("docker", append(composeArgs(root, proj, env, persistent), "port", "control", "8443")...)
	cmd.Dir = root
	cmd.Env = composeEnv(env)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return ""
	}
	return strings.TrimSpace(strings.SplitN(string(out), "\n", 2)[0])
}

func createRuntimeUser(t *testing.T, root, proj string, env labEnv) {
	t.Helper()
	res := hostJSON(t, root, proj, env, http.MethodPost, "/api/v1/users", map[string]any{
		"id": "runtime-extra", "uid": "runtime-extra", "password": "runtime-extra-password",
	})
	if res.status != http.StatusCreated && res.status != http.StatusOK && res.status != http.StatusConflict {
		t.Fatalf("create user status=%d body=%s", res.status, redactLogs(res.body, env.secrets...))
	}
}

func userExists(t *testing.T, root, proj string, env labEnv, id string) bool {
	t.Helper()
	res := hostJSON(t, root, proj, env, http.MethodGet, "/api/v1/users/"+id, nil)
	return res.status == http.StatusOK
}

func baselineRevision(t *testing.T, root, proj string, env labEnv) string {
	t.Helper()
	res := hostJSON(t, root, proj, env, http.MethodGet, "/api/v1/baseline", nil)
	if res.status != http.StatusOK {
		t.Fatalf("baseline status=%d body=%s", res.status, res.body)
	}
	var obj struct {
		ExpectedRevision string `json:"expectedRevision"`
	}
	if err := json.Unmarshal([]byte(res.body), &obj); err != nil || obj.ExpectedRevision == "" {
		t.Fatalf("baseline revision missing: %s", res.body)
	}
	return obj.ExpectedRevision
}

func execOutput(t *testing.T, secrets []string, name string, args ...string) string {
	t.Helper()
	out, err := exec.Command(name, args...).CombinedOutput()
	if err != nil {
		t.Fatalf("%s %s: %v\n%s", name, strings.Join(args, " "), err, redactLogs(string(out), secrets...))
	}
	return string(out)
}

func execCombined(args ...string) string {
	out, _ := exec.Command(args[0], args[1:]...).CombinedOutput()
	return string(out)
}

type httpResult struct {
	status int
	body   string
}

var errNoPort = errString("control has no published 8443")

type errString string

func (e errString) Error() string { return string(e) }

func httpDo(method, url, token string, body []byte) (httpResult, error) {
	var rdr io.Reader
	if body != nil {
		rdr = bytes.NewReader(body)
	}
	req, err := http.NewRequest(method, url, rdr)
	if err != nil {
		return httpResult{}, err
	}
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	client := &http.Client{
		Timeout: 10 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true}, // generated lab management cert
		},
	}
	resp, err := client.Do(req)
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

func readFile(t *testing.T, path string) string {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
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
