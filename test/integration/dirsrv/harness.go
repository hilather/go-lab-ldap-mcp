//go:build integration

package dirsrv

import (
	"bytes"
	"crypto/rand"
	"crypto/tls"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	ldap "github.com/go-ldap/ldap/v3"

	"github.com/hilather/go-lab-ldap-mcp/internal/observability"
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
	// T-148: under LABLDAP_IT_ENGINE=native the pinned 389 container harness
	// does not apply; tests that have not been parametrized skip here. The
	// documented skip ledger (Delta/Excluded IDs) is at the top of engine.go.
	skip389Only(t, "D2/D4/D5/E7", "test drives the pinned 389 DS container (docker/dsconf/in-container ldap* tooling)")
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
		"-v", "/data",
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

// ImportTLS loads generated CA + server key/cert into the running instance
// NSS DB via dsctl (not first-boot PEM bind-mounts) and restarts so LDAPS
// presents that Server-Cert. Host ports are refreshed after restart.
func (i *Instance) ImportTLS(t *testing.T, mat *TLSMaterial) {
	t.Helper()
	copies := [][2]string{
		{filepath.Join(mat.Dir, "ca", "ca.crt"), i.Name + ":/tmp/labldap-ca.crt"},
		{filepath.Join(mat.Dir, "server.crt"), i.Name + ":/tmp/labldap-server.crt"},
		{filepath.Join(mat.Dir, "server.key"), i.Name + ":/tmp/labldap-server.key"},
	}
	for _, c := range copies {
		if out, err := exec.Command("docker", "cp", c[0], c[1]).CombinedOutput(); err != nil {
			t.Fatalf("docker cp %s: %v\n%s", c[0], err, redactLogs(string(out), i.password))
		}
	}
	cmds := [][]string{
		{"dsctl", "localhost", "tls", "import-ca", "/tmp/labldap-ca.crt", "LabLDAP-Test-CA"},
		{"dsctl", "localhost", "tls", "import-server-key-cert", "/tmp/labldap-server.crt", "/tmp/labldap-server.key"},
	}
	for _, args := range cmds {
		out, err := exec.Command("docker", append([]string{"exec", i.Name}, args...)...).CombinedOutput()
		if err != nil {
			t.Fatalf("%s: %v\n%s", strings.Join(args, " "), err, redactLogs(string(out), i.password))
		}
	}
	if out, err := exec.Command("docker", "restart", i.Name).CombinedOutput(); err != nil {
		t.Fatalf("docker restart: %v\n%s", err, redactLogs(string(out), i.password))
	}
	ldapPort, err := hostPort(i.Name, "3389/tcp")
	if err != nil {
		t.Fatal(err)
	}
	ldapsPort, err := hostPort(i.Name, "3636/tcp")
	if err != nil {
		t.Fatal(err)
	}
	i.LDAPAddr = net.JoinHostPort("127.0.0.1", ldapPort)
	i.LDAPSAddr = net.JoinHostPort("127.0.0.1", ldapsPort)
	waitReady(t, i)
}

func waitReady(t *testing.T, inst *Instance) {
	t.Helper()
	// container.inf is written at the end of first-boot, after setup's
	// temporary slapd is already answering dsconf. Restarting before the
	// marker exists makes dscontainer try to create a second instance.
	deadline := time.Now().Add(90 * time.Second)
	for time.Now().Before(deadline) {
		if err := exec.Command("docker", "exec", inst.Name, "test", "-f", "/data/config/container.inf").Run(); err == nil {
			if err := exec.Command("docker", "exec", inst.Name, "test", "-S", "/data/run/slapd-localhost.socket").Run(); err == nil {
				waitTCP(t, inst.LDAPAddr, inst)
				waitTCP(t, inst.LDAPSAddr, inst)
				waitDSConf(t, inst)
				waitDMBind(t, inst)
				return
			}
		}
		time.Sleep(500 * time.Millisecond)
	}
	logs, _ := exec.Command("docker", "logs", inst.Name).CombinedOutput()
	t.Fatalf("instance marker or LDAPI socket missing\n%s", redactLogs(string(logs), inst.password))
}

// waitDMBind blocks until the Directory Manager password the tests use is
// live. On first boot the image's dscontainer creates the instance with a
// random root password, starts ns-slapd, waits for its own LDAPI health
// check, and only then applies DS_DM_PASSWORD. Every earlier readiness
// signal (container.inf, the LDAPI socket, TCP, dsconf over LDAPI autobind)
// can pass inside that window, so a DM simple bind fails with 49. Only 49 (and
// network errors) are retried, within a bound; any other error fails at
// once. Each attempt has its own dial and request timeout. After docker
// restart the password is already the persisted value, so this returns on
// the first attempt. The root DN is exempt from password policy, so failed
// binds here cannot lock it out. The bind runs from the host over LDAPS so
// the password never appears on a command line, and it works both before
// and after bootstrap enables require-secure-authentication.
func waitDMBind(t *testing.T, inst *Instance) {
	t.Helper()
	err := retryInvalidCredentials(60*time.Second, 500*time.Millisecond, func() error {
		conn, err := ldap.DialURL("ldaps://"+inst.LDAPSAddr,
			ldap.DialWithDialer(&net.Dialer{Timeout: 5 * time.Second}),
			ldap.DialWithTLSConfig(&tls.Config{InsecureSkipVerify: true, MinVersion: tls.VersionTLS12})) // readiness probe only; certificate trust is tested elsewhere
		if err != nil {
			return err
		}
		defer conn.Close()
		conn.SetTimeout(5 * time.Second)
		return conn.Bind("cn=Directory Manager", inst.password)
	})
	if err != nil {
		logs, _ := exec.Command("docker", "logs", inst.Name).CombinedOutput()
		t.Fatalf("Directory Manager bind not ready: %v\n%s", err, redactLogs(string(logs), inst.password))
	}
}

// errDMBindTimeout reports that every attempt within the bound returned 49.
var errDMBindTimeout = errors.New("DS_DM_PASSWORD was not applied in time (bind kept returning 49)")

// retryInvalidCredentials calls attempt until it succeeds, retrying only on
// LDAP result 49 until the deadline. It is separate from waitDMBind so the
// retry policy is unit-testable without Docker.
func retryInvalidCredentials(limit, interval time.Duration, attempt func() error) error {
	deadline := time.Now().Add(limit)
	for {
		err := attempt()
		if err == nil {
			return nil
		}
		// 49 is the DS_DM_PASSWORD window; a network error (EOF or reset via
		// docker-proxy) is retried within the same bound. Anything else (TLS,
		// other result codes) is returned at once.
		if !ldap.IsErrorWithCode(err, ldap.LDAPResultInvalidCredentials) && !ldap.IsErrorWithCode(err, ldap.ErrorNetwork) {
			return err
		}
		if time.Now().Add(interval).After(deadline) {
			return errDMBindTimeout
		}
		time.Sleep(interval)
	}
}

func waitDSConf(t *testing.T, inst *Instance) {
	t.Helper()
	deadline := time.Now().Add(90 * time.Second)
	for time.Now().Before(deadline) {
		if err := exec.Command("docker", "exec", inst.Name, "dsconf", "localhost", "backend", "suffix", "list").Run(); err == nil {
			return
		}
		time.Sleep(500 * time.Millisecond)
	}
	logs, _ := exec.Command("docker", "logs", inst.Name).CombinedOutput()
	t.Fatalf("dsconf not ready\n%s", redactLogs(string(logs), inst.password))
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

// Password returns the Directory Manager password set via DS_DM_PASSWORD.
func (i *Instance) Password() observability.Secret {
	if i == nil {
		return ""
	}
	return observability.Secret(i.password)
}

// WriteCA copies the instance self-signed CA to dest and returns the PEM.
func (i *Instance) WriteCA(t testing.TB, dest string) []byte {
	t.Helper()
	out, err := exec.Command("docker", "cp", i.Name+":/etc/dirsrv/slapd-localhost/ca.crt", dest).CombinedOutput()
	if err != nil {
		t.Fatalf("docker cp ca.crt: %v\n%s", err, redactLogs(string(out), i.password))
	}
	b, err := os.ReadFile(dest)
	if err != nil || len(b) == 0 {
		t.Fatalf("empty instance CA: %v", err)
	}
	return b
}

func (i *Instance) Hostname(t testing.TB) string {
	t.Helper()
	out, err := exec.Command("docker", "inspect", "-f", "{{.Config.Hostname}}", i.Name).Output()
	if err != nil {
		t.Fatal(err)
	}
	return strings.TrimSpace(string(out))
}

func (i *Instance) Stop(t testing.TB) {
	if i == nil || i.Name == "" {
		return
	}
	logs, _ := exec.Command("docker", "logs", i.Name).CombinedOutput()
	if t.Failed() {
		t.Logf("directory logs (redacted):\n%s", redactLogs(string(logs), i.password))
	}
	_ = exec.Command("docker", "rm", "-fv", i.Name).Run()
	i.Name = ""
}
