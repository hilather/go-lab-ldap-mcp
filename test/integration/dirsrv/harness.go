//go:build integration

package dirsrv

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"net"
	"os/exec"
	"strings"
	"testing"
	"time"
)

const label = "labldap.integration=1"

// Instance is a running pinned 389 DS container.
type Instance struct {
	Name      string
	LDAPAddr  string
	LDAPSAddr string
	password  string
}

func requireDocker(t *testing.T) {
	t.Helper()
	if _, err := exec.LookPath("docker"); err != nil {
		t.Skip("docker not on PATH")
	}
	if err := exec.Command("docker", "info").Run(); err != nil {
		t.Skip("docker daemon not available")
	}
}

func Start(t *testing.T) *Instance {
	t.Helper()
	requireDocker(t)
	ref, err := ImageRef()
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(ref, "@sha256:") {
		t.Fatalf("image ref is not a digest pin: %s", ref)
	}
	if err := exec.Command("docker", "image", "inspect", ref).Run(); err != nil {
		pull := exec.Command("docker", "pull", ref)
		if out, perr := pull.CombinedOutput(); perr != nil {
			t.Fatalf("docker pull %s: %v\n%s", ref, perr, redactLogs(string(out)))
		}
	}

	pw := randomSecret()
	name := "labldap-it-" + randomID()
	args := []string{
		"run", "-d", "--name", name,
		"--label", label,
		"-e", "DS_DM_PASSWORD=" + pw,
		"-p", "127.0.0.1::3389",
		"-p", "127.0.0.1::3636",
		ref,
	}
	out, err := exec.Command("docker", args...).CombinedOutput()
	if err != nil {
		t.Fatalf("docker run: %v\n%s", err, redactLogs(string(out), pw))
	}

	inst := &Instance{Name: name, password: pw}
	t.Cleanup(func() { inst.Stop(t) })

	ldapPort, err := hostPort(name, "3389/tcp")
	if err != nil {
		t.Fatal(err)
	}
	ldapsPort, err := hostPort(name, "3636/tcp")
	if err != nil {
		t.Fatal(err)
	}
	inst.LDAPAddr = net.JoinHostPort("127.0.0.1", ldapPort)
	inst.LDAPSAddr = net.JoinHostPort("127.0.0.1", ldapsPort)

	waitReady(t, inst)
	return inst
}

func waitReady(t *testing.T, inst *Instance) {
	t.Helper()
	// container.inf is written before ns-slapd is up. The LDAPI socket is
	// the contract readiness signal; TCP on 3389/3636 follows.
	deadline := time.Now().Add(90 * time.Second)
	for time.Now().Before(deadline) {
		if err := exec.Command("docker", "exec", inst.Name, "test", "-S", "/data/run/slapd-localhost.socket").Run(); err == nil {
			waitTCP(t, inst.LDAPAddr, inst)
			waitTCP(t, inst.LDAPSAddr, inst)
			return
		}
		time.Sleep(500 * time.Millisecond)
	}
	logs, _ := exec.Command("docker", "logs", inst.Name).CombinedOutput()
	t.Fatalf("LDAPI socket /data/run/slapd-localhost.socket missing\n%s", redactLogs(string(logs), inst.password))
}

func waitTCP(t *testing.T, addr string, inst *Instance) {
	t.Helper()
	deadline := time.Now().Add(90 * time.Second)
	for time.Now().Before(deadline) {
		c, err := net.DialTimeout("tcp", addr, time.Second)
		if err == nil {
			_ = c.Close()
			return
		}
		time.Sleep(500 * time.Millisecond)
	}
	logs, _ := exec.Command("docker", "logs", inst.Name).CombinedOutput()
	t.Fatalf("389 DS did not accept %s\n%s", addr, redactLogs(string(logs), inst.password))
}

func hostPort(name, spec string) (string, error) {
	out, err := exec.Command("docker", "port", name, spec).Output()
	if err != nil {
		return "", fmt.Errorf("docker port %s %s: %w", name, spec, err)
	}
	// 127.0.0.1:32768
	line := strings.TrimSpace(string(out))
	_, port, err := net.SplitHostPort(strings.TrimSpace(strings.Split(line, "\n")[0]))
	return port, err
}

func randomID() string {
	var b [6]byte
	_, _ = rand.Read(b[:])
	return hex.EncodeToString(b[:])
}

func randomSecret() string {
	var b [16]byte
	_, _ = rand.Read(b[:])
	return hex.EncodeToString(b[:])
}

func runningLabeled() ([]string, error) {
	out, err := exec.Command("docker", "ps", "-aq", "--filter", "label="+label).Output()
	if err != nil {
		return nil, err
	}
	var ids []string
	for _, l := range bytes.Split(bytes.TrimSpace(out), []byte("\n")) {
		if len(l) > 0 {
			ids = append(ids, string(l))
		}
	}
	return ids, nil
}

func (i *Instance) Stop(t testing.TB) {
	if i == nil || i.Name == "" {
		return
	}
	logs, _ := exec.Command("docker", "logs", i.Name).CombinedOutput()
	if t.Failed() {
		t.Logf("directory logs (redacted):\n%s", redactLogs(string(logs), i.password))
	}
	_ = exec.Command("docker", "rm", "-f", i.Name).Run()
	i.Name = ""
}
