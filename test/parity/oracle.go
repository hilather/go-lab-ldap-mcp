//go:build integration

package parity

import (
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"

	ldap "github.com/go-ldap/ldap/v3"
)

// oracleEngine runs the pinned 389 DS image in Docker and applies the
// same dsconf configuration the production reconcilers apply. It is a
// self-contained launcher (mirroring test/integration/dirsrv/harness.go)
// because the harness package is an application test package, not a
// library for importers.
type oracleEngine struct {
	fx        *fixture
	cname     string // container name
	ldapAddr  string
	ldapsAddr string
	password  string // Directory Manager secret; never logged
	hostname  string
	pool      *x509.CertPool
	wrong     *x509.CertPool
}

const oracleLabel = "labldap.parity=1"

// startOracle starts the oracle or skips when Docker is unavailable.
func startOracle(t *testing.T, fx *fixture) *oracleEngine {
	t.Helper()
	if _, err := exec.LookPath("docker"); err != nil {
		t.Skip("docker not on PATH: skipping dual-engine oracle run")
	}
	if err := exec.Command("docker", "info").Run(); err != nil {
		t.Skip("docker daemon unavailable: skipping dual-engine oracle run")
	}
	ref, err := parityImageRef()
	if err != nil {
		t.Fatalf("parity: image ref: %v", err)
	}
	if !strings.Contains(ref, "@sha256:") {
		t.Fatalf("parity: image ref is not a digest pin: %s", ref)
	}
	if err := exec.Command("docker", "image", "inspect", ref).Run(); err != nil {
		pull := exec.Command("docker", "pull", ref)
		if out, perr := pull.CombinedOutput(); perr != nil {
			t.Fatalf("parity: docker pull %s: %v\n%s", ref, perr, oracleRedact(string(out)))
		}
	}

	pw := parityRandomSecret()
	name := "labldap-parity-" + parityRandomID()
	args := []string{
		"run", "-d", "--name", name,
		"--label", oracleLabel,
		"-e", "DS_DM_PASSWORD=" + pw,
		"-p", "127.0.0.1::3389",
		"-p", "127.0.0.1::3636",
		"-v", "/data",
		ref,
	}
	if out, err := exec.Command("docker", args...).CombinedOutput(); err != nil {
		t.Fatalf("parity: docker run: %v\n%s", err, oracleRedact(string(out), pw))
	}
	e := &oracleEngine{fx: fx, cname: name, password: pw}
	t.Cleanup(func() {
		if e.cname == "" {
			return
		}
		if t.Failed() {
			logs, _ := exec.Command("docker", "logs", e.cname).CombinedOutput()
			t.Logf("389 container logs (redacted):\n%s", oracleRedact(string(logs), pw))
		}
		_ = exec.Command("docker", "rm", "-fv", e.cname).Run()
		e.cname = ""
	})

	e.ldapAddr = net.JoinHostPort("127.0.0.1", mustHostPort(t, name, "3389/tcp"))
	e.ldapsAddr = net.JoinHostPort("127.0.0.1", mustHostPort(t, name, "3636/tcp"))
	e.waitReady(t)
	e.hostname = e.readHostname(t)

	// Trust the container's self-signed first-boot CA for correct-probes;
	// a wrong pool for the badCA probes.
	caPEM := e.writeCA(t, filepath.Join(t.TempDir(), "ca.pem"))
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(caPEM) {
		t.Fatal("parity: oracle CA PEM did not parse")
	}
	e.pool = pool
	wrong := x509.NewCertPool()
	wrongPEM, _, _ := makeCA(t, "LabLDAP Parity Wrong CA")
	if !wrong.AppendCertsFromPEM(wrongPEM) {
		t.Fatal("parity: wrong CA PEM did not parse")
	}
	e.wrong = wrong

	e.configure389(t)

	// Seed exactly like native does.
	conn, err := e.dial(t, dialSpec{ldaps: true, bindDN: "cn=Directory Manager", bindPass: pw})
	if err != nil {
		t.Fatalf("parity: oracle DM dial: %v", err)
	}
	seedDirectory(t, fx, conn)
	conn.Close()

	// Production runs the MemberOf fix-up task after configuration
	// (plugins.go); with the plugin enabled during seeding this is a
	// no-op, but run it to mirror the reconciler exactly.
	e.dsconf(t, "plugin", "memberof", "fixup", "--wait", "--timeout", "60", suffixDN)
	return e
}

func (e *oracleEngine) name() string { return "389" }

// dmSecret returns the per-instance DM password for bind credentials.
// It is used only as a credential, never recorded in an outcome or the
// ledger.
func (e *oracleEngine) dmSecret() string { return e.password }

// configure389 applies the production reconciler configuration, mirroring
// internal/directory/ds389 argument vectors exactly (backend.go,
// plugins.go, pwpolicy.go, tls.go), so the oracle is configured the way
// labldap-bootstrap would configure it.
func (e *oracleEngine) configure389(t *testing.T) {
	t.Helper()
	p := e.fx.compiled.Engine.PasswordPolicy

	e.dsconf(t, "backend", "create", "--suffix", suffixDN, "--be-name", e.fx.compiled.Engine.BackendName, "--create-suffix")

	// Plugins (plugins.go): dynamic plugin state, then enable+set each.
	e.dsconf(t, "config", "replace", "nsslapd-dynamic-plugins=on")
	e.dsconf(t, "plugin", "memberof", "enable")
	e.dsconf(t, "plugin", "memberof", "set",
		"--attr", "memberOf", "--groupattr", "member",
		"--scope", suffixDN, "--autoaddoc", "nsmemberof")
	e.dsconf(t, "plugin", "referential-integrity", "enable")
	e.dsconf(t, "plugin", "referential-integrity", "set",
		"--update-delay", "0", "--membership-attr", "member",
		"--entry-scope", suffixDN, "--container-scope", suffixDN)

	// Password policy (pwpolicy.go policySetArgs), from the same compiled
	// NormalizedPolicy the native engine receives.
	e.dsconf(t, "pwpolicy", "set",
		"--pwdscheme", "PBKDF2-SHA256",
		"--pwdminlen", itoa(p.MinLength), "--pwdchecksyntax", "on",
		"--pwdmincatagories", "1", "--pwdmintokenlen", "64",
		"--pwddictcheck", "off", "--pwdpalindrome", "off",
		"--pwdhistory", "on", "--pwdhistorycount", itoa(p.HistoryCount),
		"--pwdexpire", "off",
		"--pwdwarning", "0",
		"--pwdlockout", "on", "--pwdunlock", "on",
		"--pwdmaxfailures", itoa(p.MaxFailures),
		"--pwdlockoutduration", itoa(int(p.LockoutDuration.Seconds())))

	// Bind policy (tls.go applyBindPolicy): deny anonymous, require secure
	// authentication (the fixture sets allowCleartextBind=false).
	e.dsconf(t, "security", "set", "--require-secure-authentication", "on")
	e.dsconf(t, "config", "replace", "nsslapd-allow-anonymous-access=off")
}

// dsconf runs an argument vector inside the container (never a shell),
// using LDAPI root autobind with JSON (non-interactive) mode.
func (e *oracleEngine) dsconf(t *testing.T, args ...string) {
	t.Helper()
	full := append([]string{"exec", e.cname, "dsconf", "-j", "localhost"}, args...)
	out, err := exec.Command("docker", full...).CombinedOutput()
	if err != nil {
		t.Fatalf("parity: dsconf %s: %v\n%s", strings.Join(args, " "), err, oracleRedact(string(out), e.password))
	}
}

// clientTLSFor builds the client TLS config for a dial spec.
func (e *oracleEngine) clientTLSFor(spec dialSpec) *tls.Config {
	pool := e.pool
	if spec.badCA {
		pool = e.wrong
	}
	serverName := e.hostname
	if spec.badName {
		serverName = "not-the-389.example.invalid"
	}
	return &tls.Config{RootCAs: pool, ServerName: serverName, MinVersion: tls.VersionTLS12}
}

func (e *oracleEngine) dial(t *testing.T, spec dialSpec) (*ldap.Conn, error) {
	t.Helper()
	var (
		conn *ldap.Conn
		err  error
	)
	switch {
	case spec.ldaps:
		conn, err = ldap.DialURL("ldaps://"+e.ldapsAddr, ldap.DialWithTLSConfig(e.clientTLSFor(spec)))
	case spec.startTLS:
		conn, err = ldap.DialURL("ldap://" + e.ldapAddr)
		if err == nil {
			if err = conn.StartTLS(e.clientTLSFor(spec)); err != nil {
				conn.Close()
				return nil, err
			}
		}
	default:
		conn, err = ldap.DialURL("ldap://" + e.ldapAddr)
	}
	if err != nil {
		return nil, err
	}
	if spec.noBind {
		return conn, nil
	}
	if err := conn.Bind(spec.bindDN, spec.bindPass); err != nil {
		conn.Close()
		return nil, err
	}
	return conn, nil
}

func (e *oracleEngine) dm(t *testing.T) *ldap.Conn {
	t.Helper()
	conn, err := e.dial(t, dialSpec{ldaps: true, bindDN: "cn=Directory Manager", bindPass: e.password})
	if err != nil {
		t.Fatalf("parity: oracle dm dial: %v", err)
	}
	return conn
}

// close is a no-op; container removal is registered with t.Cleanup.
func (e *oracleEngine) close(t *testing.T) { t.Helper() }

func (e *oracleEngine) addr(ldaps bool) string {
	if ldaps {
		return e.ldapsAddr
	}
	return e.ldapAddr
}

func (e *oracleEngine) clientTLS() *tls.Config { return e.clientTLSFor(dialSpec{ldaps: true}) }

func (e *oracleEngine) caFile(t *testing.T) string {
	t.Helper()
	dest := filepath.Join(t.TempDir(), "ca.pem")
	e.writeCA(t, dest)
	return dest
}

func (e *oracleEngine) serverName() string { return e.hostname }

// --- container lifecycle helpers (mirrors dirsrv/harness.go) ---

func parityImageRef() (string, error) {
	dir, err := os.Getwd()
	if err != nil {
		return "", err
	}
	for {
		b, rerr := os.ReadFile(filepath.Join(dir, "deploy", "docker", "dirsrv.digest"))
		if rerr == nil {
			return strings.TrimSpace(string(b)), nil
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			return "", fmt.Errorf("deploy/docker/dirsrv.digest not found from any parent: %w", err)
		}
		dir = parent
	}
}

func mustHostPort(t *testing.T, name, spec string) string {
	t.Helper()
	out, err := exec.Command("docker", "port", name, spec).Output()
	if err != nil {
		t.Fatalf("parity: docker port %s %s: %v", name, spec, err)
	}
	line := strings.TrimSpace(strings.Split(strings.TrimSpace(string(out)), "\n")[0])
	_, port, err := net.SplitHostPort(line)
	if err != nil {
		t.Fatalf("parity: parse host port %q: %v", line, err)
	}
	return port
}

func (e *oracleEngine) waitReady(t *testing.T) {
	t.Helper()
	// container.inf is written at the end of first-boot; restarting before
	// it exists makes dscontainer try to create a second instance.
	deadline := time.Now().Add(90 * time.Second)
	for time.Now().Before(deadline) {
		if err := exec.Command("docker", "exec", e.cname, "test", "-f", "/data/config/container.inf").Run(); err == nil {
			if err := exec.Command("docker", "exec", e.cname, "test", "-S", "/data/run/slapd-localhost.socket").Run(); err == nil {
				e.waitTCP(t, e.ldapAddr)
				e.waitTCP(t, e.ldapsAddr)
				e.waitDSConf(t)
				return
			}
		}
		time.Sleep(500 * time.Millisecond)
	}
	logs, _ := exec.Command("docker", "logs", e.cname).CombinedOutput()
	t.Fatalf("parity: 389 instance marker or LDAPI socket missing\n%s", oracleRedact(string(logs), e.password))
}

func (e *oracleEngine) waitDSConf(t *testing.T) {
	t.Helper()
	deadline := time.Now().Add(90 * time.Second)
	for time.Now().Before(deadline) {
		if err := exec.Command("docker", "exec", e.cname, "dsconf", "localhost", "backend", "suffix", "list").Run(); err == nil {
			return
		}
		time.Sleep(500 * time.Millisecond)
	}
	logs, _ := exec.Command("docker", "logs", e.cname).CombinedOutput()
	t.Fatalf("parity: dsconf not ready\n%s", oracleRedact(string(logs), e.password))
}

func (e *oracleEngine) waitTCP(t *testing.T, addr string) {
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
	logs, _ := exec.Command("docker", "logs", e.cname).CombinedOutput()
	t.Fatalf("parity: 389 DS did not accept %s\n%s", addr, oracleRedact(string(logs), e.password))
}

func (e *oracleEngine) writeCA(t *testing.T, dest string) []byte {
	t.Helper()
	if out, err := exec.Command("docker", "cp", e.cname+":/etc/dirsrv/slapd-localhost/ca.crt", dest).CombinedOutput(); err != nil {
		t.Fatalf("parity: docker cp ca.crt: %v\n%s", err, oracleRedact(string(out), e.password))
	}
	b, err := os.ReadFile(dest)
	if err != nil || len(b) == 0 {
		t.Fatalf("parity: empty instance CA: %v", err)
	}
	return b
}

func (e *oracleEngine) readHostname(t *testing.T) string {
	t.Helper()
	out, err := exec.Command("docker", "inspect", "-f", "{{.Config.Hostname}}", e.cname).Output()
	if err != nil {
		t.Fatalf("parity: docker inspect hostname: %v", err)
	}
	return strings.TrimSpace(string(out))
}

func parityRandomID() string {
	var b [6]byte
	_, _ = rand.Read(b[:])
	return hex.EncodeToString(b[:])
}

func parityRandomSecret() string {
	var b [16]byte
	_, _ = rand.Read(b[:])
	return hex.EncodeToString(b[:])
}

// --- log redaction (mirrors dirsrv/redact.go) ---

var (
	oraclePemPrivate = regexp.MustCompile(`-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----[\s\S]*?-----END [A-Z0-9 ]*PRIVATE KEY-----`)
	oraclePwAssign   = regexp.MustCompile(`(?i)((?:set )?cn=Directory Manager password to |password set to |Root DN password: |DS_DM_PASSWORD=)("?)([^"\s]+)("?)`)
)

func oracleRedact(s string, secrets ...string) string {
	s = oraclePemPrivate.ReplaceAllString(s, "[redacted-pem]")
	s = oraclePwAssign.ReplaceAllString(s, "${1}${2}[redacted]${4}")
	for _, sec := range secrets {
		if sec != "" {
			s = strings.ReplaceAll(s, sec, "[redacted]")
		}
	}
	return s
}
