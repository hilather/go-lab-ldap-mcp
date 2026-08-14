//go:build integration

package compose

import (
	"encoding/json"
	"os/exec"
	"strings"
	"testing"
)

func TestComposeControlInspectHardening(t *testing.T) {
	root := requireCompose(t)
	proj := composeProject(t, "ins")
	dir := t.TempDir()
	env := writeLabMaterial(t, root, dir)
	t.Cleanup(func() { compose(t, root, proj, env, false, "down", "--remove-orphans", "-v") })
	upStack(t, root, proj, env, false)

	cid := strings.TrimSpace(composeOutput(t, root, proj, env, false, "ps", "-q", "control"))
	if cid == "" {
		t.Fatal("control id missing")
	}
	raw := execOutput(t, env.secrets, "docker", "inspect", cid)
	var docs []inspectDoc
	if err := json.Unmarshal([]byte(raw), &docs); err != nil || len(docs) != 1 {
		t.Fatalf("inspect json: %v\n%s", err, redactLogs(raw, env.secrets...))
	}
	doc := docs[0]
	if doc.HostConfig.Privileged {
		t.Fatal("control is privileged")
	}
	if doc.Config.User != "65532:65532" && doc.Config.User != "65532" {
		t.Fatalf("control user = %q", doc.Config.User)
	}
	if len(doc.HostConfig.CapAdd) > 0 {
		t.Fatalf("control cap_add = %v", doc.HostConfig.CapAdd)
	}
	dropped := strings.Join(doc.HostConfig.CapDrop, ",")
	if !strings.Contains(strings.ToUpper(dropped), "ALL") {
		t.Fatalf("control cap_drop = %v", doc.HostConfig.CapDrop)
	}
	if !doc.HostConfig.ReadonlyRootfs {
		t.Fatal("control rootfs is writable")
	}
	for _, e := range doc.Config.Env {
		if strings.HasPrefix(e, "DS_DM_PASSWORD=") {
			t.Fatal("control env has DS_DM_PASSWORD")
		}
		for _, sec := range env.secrets {
			if sec != "" && strings.Contains(e, sec) {
				t.Fatal("control env contains a generated secret")
			}
		}
		for _, fix := range []string{"lab-fixture-admin-token", "lab-fixture-alice-password", "lab-fixture-runtime-password"} {
			if strings.Contains(e, fix) {
				t.Fatalf("control env contains fixture %q", fix)
			}
		}
	}
	for _, m := range doc.Mounts {
		joined := m.Source + " " + m.Destination
		if strings.Contains(joined, "docker.sock") || strings.Contains(joined, "dm.pw") || strings.Contains(joined, "ca.key") {
			t.Fatalf("forbidden mount: %s", joined)
		}
	}
	for _, p := range []string{"3389/tcp", "3636/tcp"} {
		assertLoopbackPublish(t, root, proj, env, "directory", p)
	}
	assertLoopbackPublish(t, root, proj, env, "control", "8443/tcp")
}

func assertLoopbackPublish(t *testing.T, root, proj string, env labEnv, service, port string) {
	t.Helper()
	out := composeOutput(t, root, proj, env, false, "port", service, strings.TrimSuffix(port, "/tcp"))
	line := strings.TrimSpace(strings.SplitN(out, "\n", 2)[0])
	if !strings.HasPrefix(line, "127.0.0.1:") && !strings.HasPrefix(line, "[::1]:") {
		t.Fatalf("%s %s published on %q, want loopback", service, port, line)
	}
}

func TestImageHistoryHasNoFixtures(t *testing.T) {
	if exec.Command("docker", "image", "inspect", "labldap-control:dev").Run() != nil {
		t.Skip("labldap-control:dev not built")
	}
	out, err := exec.Command("docker", "history", "--no-trunc", "--format", "{{.CreatedBy}}", "labldap-control:dev").CombinedOutput()
	if err != nil {
		t.Fatal(err)
	}
	text := string(out)
	for _, s := range []string{"lab-fixture-admin-token", "lab-fixture-alice-password", "DS_DM_PASSWORD=", "docker.sock"} {
		if strings.Contains(text, s) {
			t.Fatalf("history contains %q", s)
		}
	}
}

type inspectDoc struct {
	Config struct {
		User string   `json:"User"`
		Env  []string `json:"Env"`
	} `json:"Config"`
	HostConfig struct {
		Privileged     bool     `json:"Privileged"`
		CapAdd         []string `json:"CapAdd"`
		CapDrop        []string `json:"CapDrop"`
		ReadonlyRootfs bool     `json:"ReadonlyRootfs"`
	} `json:"HostConfig"`
	Mounts []struct {
		Source      string `json:"Source"`
		Destination string `json:"Destination"`
	} `json:"Mounts"`
}
