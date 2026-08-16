//go:build integration

package dirsrv

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/hilather/go-lab-ldap-mcp/test/compatibility/goindep"
)

// compatEnv is the engine endpoint the T-115 client matrix runs against
// (T-148 parametrization; engine selected by LABLDAP_IT_ENGINE, see
// engine.go). Client subtests consume only this surface, so the same
// expectations apply to both engines wherever the parity contract is
// Contract-tier; intentional differences carry a Delta ID inline.
type compatEnv struct {
	engine     string // Engine389DS or EngineNative
	ldapAddr   string // host:port, cleartext listener (StartTLS only)
	ldapsAddr  string // host:port, implicit TLS
	caFile     string // test CA that signed the directory server cert
	serverName string // TLS name clients verify ("localhost")
	dmPassword string // Directory Manager password for this run
}

// startCompatEngine stages the selected engine for the matrix. The 389 path
// is the shipped container flow (bootstrap binary exec'd inside the pinned
// image, dsctl TLS import); the native path is the in-process fixture
// (native.go) with the identical scenario compiled and applied over LDAP.
func startCompatEngine(t *testing.T) compatEnv {
	t.Helper()
	return startCompatEngineFromYAML(t, seedYAML("merge"))
}

func startCompatEngineFromYAML(t *testing.T, yaml string) compatEnv {
	t.Helper()
	if itEngine(t) == EngineNative {
		n := startNative(t, yaml)
		return compatEnv{
			engine:     EngineNative,
			ldapAddr:   n.LDAPAddr,
			ldapsAddr:  n.LDAPSAddr,
			caFile:     n.CAFile,
			serverName: n.ServerName,
			dmPassword: n.dmPassword,
		}
	}
	inst := Start(t)
	_, guest := stageSeedApply(t, inst, yaml, seedCanary)
	out, err := execApply(t, inst, guest, nil)
	if err != nil {
		t.Fatalf("apply: %v\n%s", err, redactLogs(out, seedCanary, inst.password))
	}
	mat := generateTLS(t, "localhost")
	inst.ImportTLS(t, mat)
	return compatEnv{
		engine:     Engine389DS,
		ldapAddr:   inst.LDAPAddr,
		ldapsAddr:  inst.LDAPSAddr,
		caFile:     filepath.Join(mat.Dir, "ca", "ca.crt"),
		serverName: "localhost",
		dmPassword: inst.Password().Reveal(),
	}
}

func workflowYAML() string {
	return `apiVersion: labldap.dev/v1alpha1
kind: LabScenario
metadata: { name: workflow }
spec:
  directory: { suffix: "dc=example,dc=test" }
  lifecycle: { startupMode: merge }
  transport: { ldaps: { enabled: true, port: 3636 } }
  runtimeAccount: { id: rt, passwordFile: secrets/runtime-ldap }
  users:
    - id: alice
      uid: alice
      passwordFile: secrets/user-alice
      enabled: true
      attributes: { sn: Seed }
  groups:
    - id: staff
      members:
        - user: alice
  passwordPolicy:
    minLength: 12
    historyCount: 0
    maxAge: 0s
    warningAge: 0s
    lockout: { enabled: true, maxFailures: 5, lockoutDuration: 60s }
    storageScheme: PBKDF2-SHA256
`
}

func TestCompatibilityLDAPClients(t *testing.T) {
	env := startCompatEngine(t)
	ca := env.caFile

	recordClientVersions(t)

	// Parity contract Delta D1 (vendor identity): record the selected
	// engine's Root DSE identity for the compatibility report and assert
	// the engines differ — native must not fake 389 strings.
	t.Run("engine_identity_D1", func(t *testing.T) {
		requireHostTool(t, "ldapsearch")
		out := hostLDAPSearch(t, env, "cn=Directory Manager", env.dmPassword,
			"", "base", "(objectClass=*)", "vendorName", "vendorVersion")
		t.Logf("compatibility report: engine=%s\n%s", env.engine, out)
		switch env.engine {
		case EngineNative:
			if !strings.Contains(out, "vendorName: LabLDAP") {
				t.Fatalf("native vendorName missing (D1):\n%s", out)
			}
			if strings.Contains(out, "389-Directory") {
				t.Fatalf("native must not present 389 identity (D1):\n%s", out)
			}
		default:
			if !strings.Contains(out, "389-Directory/") {
				t.Fatalf("389 vendorVersion missing (oracle identity):\n%s", out)
			}
		}
	})

	t.Run("ldapsearch_ldaps", func(t *testing.T) {
		requireHostTool(t, "ldapsearch")
		got := hostLDAPSearch(t, env, "cn=Directory Manager", env.dmPassword,
			"dc=example,dc=test", "sub", "(uid=alice)", "uid", "memberOf")
		if !strings.Contains(got, "uid: alice") {
			t.Fatalf("missing alice:\n%s", got)
		}
	})

	// Contract C1/C2: StartTLS then WhoAmI. The authzid rendering differs in
	// case preservation (delta candidate CAND-20), so the assertion accepts
	// any rendering carrying the uid.
	t.Run("ldapwhoami_starttls", func(t *testing.T) {
		requireHostTool(t, "ldapwhoami")
		pw := writePW(t, seedCanary)
		cmd := exec.Command("ldapwhoami", "-x", "-ZZ",
			"-H", "ldap://"+env.ldapAddr,
			"-o", "tls_reqcert=demand",
			"-o", "tls_cacert="+ca,
			"-D", "uid=alice,ou=people,dc=example,dc=test", "-y", pw)
		got, err := cmd.CombinedOutput()
		if err != nil {
			t.Fatalf("%v\n%s", err, redactLogs(string(got), seedCanary))
		}
		if !strings.Contains(string(got), "alice") {
			t.Fatalf("whoami = %s", got)
		}
	})

	// Contract C6/C9: Simple Paged Results over LDAPS.
	t.Run("ldapsearch_paging", func(t *testing.T) {
		requireHostTool(t, "ldapsearch")
		pw := writePW(t, env.dmPassword)
		cmd := exec.Command("ldapsearch", "-x", "-LLL",
			"-H", "ldaps://"+env.ldapsAddr,
			"-o", "tls_reqcert=demand",
			"-o", "tls_cacert="+ca,
			"-D", "cn=Directory Manager", "-y", pw,
			"-E", "pr=2/noprompt",
			"-b", "dc=example,dc=test", "(objectClass=inetOrgPerson)", "uid")
		got, err := cmd.CombinedOutput()
		if err != nil {
			t.Fatalf("%v\n%s", err, redactLogs(string(got), env.dmPassword))
		}
		if !strings.Contains(string(got), "uid: alice") {
			t.Fatalf("page missing alice:\n%s", got)
		}
	})

	// Contract C11: password change is an attribute replace on userPassword
	// (RFC 3062 is Excluded E3), then a fresh bind with the new secret.
	t.Run("password_modify_and_rebind", func(t *testing.T) {
		requireHostTool(t, "ldapmodify")
		neu := seedCanary + "X"
		pw := writePW(t, env.dmPassword)
		replacePassword := func(value string) {
			t.Helper()
			ldif := "dn: uid=alice,ou=people,dc=example,dc=test\nchangetype: modify\nreplace: userPassword\nuserPassword: " + value + "\n"
			cmd := exec.Command("ldapmodify", "-x",
				"-H", "ldaps://"+env.ldapsAddr,
				"-o", "tls_reqcert=demand",
				"-o", "tls_cacert="+ca,
				"-D", "cn=Directory Manager", "-y", pw)
			cmd.Stdin = strings.NewReader(ldif)
			if out, err := cmd.CombinedOutput(); err != nil {
				t.Fatalf("ldapmodify: %v\n%s", err, redactLogs(string(out), env.dmPassword, seedCanary, neu))
			}
		}
		replacePassword(neu)
		if err := envBind(t, env, "uid=alice,ou=people,dc=example,dc=test", neu); err != nil {
			t.Fatalf("rebind: %v", err)
		}
		replacePassword(seedCanary)
	})

	t.Run("go_independent", func(t *testing.T) {
		who, dns, err := goindep.SearchWhoami(goindep.Config{
			URL:        "ldaps://" + env.ldapsAddr,
			CAFile:     ca,
			ServerName: env.serverName,
			BindDN:     "cn=Directory Manager",
			Password:   env.dmPassword,
			BaseDN:     "dc=example,dc=test",
			Filter:     "(uid=alice)",
			PageSize:   2,
		})
		if err != nil {
			t.Fatal(err)
		}
		found := false
		for _, dn := range dns {
			if strings.Contains(dn, "uid=alice") {
				found = true
			}
		}
		if !found {
			t.Fatalf("whoami=%q dns=%v", who, dns)
		}
		_, _, err = goindep.SearchWhoami(goindep.Config{
			URL:        "ldap://" + env.ldapAddr,
			StartTLS:   true,
			CAFile:     ca,
			ServerName: env.serverName,
			BindDN:     "cn=Directory Manager",
			Password:   env.dmPassword,
			BaseDN:     "dc=example,dc=test",
			Filter:     "(uid=alice)",
			PageSize:   2,
		})
		if err != nil {
			t.Fatalf("go starttls: %v", err)
		}
		// Contract C2: cleartext simple bind is refused when
		// allowCleartextBind is false (both engines).
		_, _, err = goindep.SearchWhoami(goindep.Config{
			URL:      "ldap://" + env.ldapAddr,
			BindDN:   "cn=Directory Manager",
			Password: env.dmPassword,
			BaseDN:   "dc=example,dc=test",
			Filter:   "(uid=alice)",
		})
		if err == nil {
			t.Fatal("cleartext LDAP bind must fail when allowCleartextBind is false")
		}
	})

	t.Run("python_ldap3", func(t *testing.T) {
		runPythonClient(t, env, ca, false)
		runPythonClient(t, env, ca, true)
	})

	// Contract C8: alice has no grant on any engine-admin tree, and group
	// membership is visible. Delta D2: native has no 389 cn=config DIT, so
	// the native expectation is absence-or-denial; the 389 oracle denies.
	t.Run("aci_alice_read_no_config", func(t *testing.T) {
		out := hostLDAPSearchAllowFail(t, env, "uid=alice,ou=people,dc=example,dc=test", seedCanary,
			"cn=config", "base", "(objectClass=*)", "dn")
		if strings.Contains(out, "dn: cn=config") {
			t.Fatalf("alice must not read cn=config:\n%s", out)
		}
		staff := hostLDAPSearch(t, env, "cn=Directory Manager", env.dmPassword,
			"cn=staff,ou=groups,dc=example,dc=test", "base", "(objectClass=*)", "member")
		if !strings.Contains(staff, "uid=alice") {
			t.Fatalf("membership missing:\n%s", staff)
		}
	})

	// Contract C3: anonymous bind is off by default; even if a server let
	// the search through, no runtime ACI grants anonymous anything.
	t.Run("anonymous_denied", func(t *testing.T) {
		requireHostTool(t, "ldapsearch")
		cmd := exec.Command("ldapsearch", "-x", "-LLL",
			"-H", "ldaps://"+env.ldapsAddr,
			"-o", "tls_reqcert=demand",
			"-o", "tls_cacert="+ca,
			"-b", "dc=example,dc=test", "(uid=alice)", "uid")
		got, err := cmd.CombinedOutput()
		if err == nil && strings.Contains(string(got), "uid: alice") {
			t.Fatalf("anonymous search must not return alice:\n%s", got)
		}
	})
}

// hostLDAPSearch runs the host OpenLDAP ldapsearch against the selected
// engine over LDAPS with strict certificate verification and fails on error.
func hostLDAPSearch(t *testing.T, env compatEnv, bindDN, password, base, scope, filter string, attrs ...string) string {
	t.Helper()
	out, err := runHostLDAPSearch(t, env, bindDN, password, base, scope, filter, attrs...)
	if err != nil {
		t.Fatalf("ldapsearch %s: %v\n%s", base, err, redactLogs(out, env.dmPassword, seedCanary))
	}
	return out
}

// hostLDAPSearchAllowFail returns the search output even when the server
// refuses the operation (access-denied assertions).
func hostLDAPSearchAllowFail(t *testing.T, env compatEnv, bindDN, password, base, scope, filter string, attrs ...string) string {
	t.Helper()
	out, _ := runHostLDAPSearch(t, env, bindDN, password, base, scope, filter, attrs...)
	return out
}

func runHostLDAPSearch(t *testing.T, env compatEnv, bindDN, password, base, scope, filter string, attrs ...string) (string, error) {
	t.Helper()
	requireHostTool(t, "ldapsearch")
	pw := writePW(t, password)
	args := []string{"-x", "-LLL",
		"-H", "ldaps://" + env.ldapsAddr,
		"-o", "tls_reqcert=demand",
		"-o", "tls_cacert=" + env.caFile,
		"-D", bindDN, "-y", pw,
		"-b", base, "-s", scope, filter}
	args = append(args, attrs...)
	out, err := exec.Command("ldapsearch", args...).CombinedOutput()
	return string(out), err
}

// envBind checks one bind through the independent Go client (go-ldap),
// engine-agnostic by construction.
func envBind(t *testing.T, env compatEnv, dn, password string) error {
	t.Helper()
	_, _, err := goindep.SearchWhoami(goindep.Config{
		URL:        "ldaps://" + env.ldapsAddr,
		CAFile:     env.caFile,
		ServerName: env.serverName,
		BindDN:     dn,
		Password:   password,
		BaseDN:     dn,
		Filter:     "(objectClass=*)",
	})
	return err
}

func writePW(t *testing.T, value string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "pw")
	// OpenLDAP 2.6 -y uses the complete file, including a trailing newline.
	if err := os.WriteFile(p, []byte(value), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

func inCI() bool {
	return os.Getenv("CI") != "" || os.Getenv("GITHUB_ACTIONS") != ""
}

func requireHostTool(t *testing.T, name string) {
	t.Helper()
	if _, err := exec.LookPath(name); err != nil {
		if inCI() {
			t.Fatalf("%s is required in CI: %v", name, err)
		}
		t.Skipf("%s not on PATH", name)
	}
}

func recordClientVersions(t *testing.T) {
	t.Helper()
	if out, err := exec.Command("ldapsearch", "-VV").CombinedOutput(); err == nil || len(out) > 0 {
		t.Logf("ldapsearch: %s", strings.TrimSpace(string(out)))
	}
	if out, err := exec.Command("ldapmodify", "-VV").CombinedOutput(); err == nil || len(out) > 0 {
		t.Logf("ldapmodify: %s", strings.TrimSpace(string(out)))
	}
	if out, err := exec.Command("go", "list", "-m", "github.com/go-ldap/ldap/v3").CombinedOutput(); err == nil {
		t.Logf("go-ldap: %s", strings.TrimSpace(string(out)))
	}
}

func runPythonClient(t *testing.T, env compatEnv, ca string, startTLS bool) {
	t.Helper()
	requireHostTool(t, "python3")
	root, err := moduleRoot()
	if err != nil {
		t.Fatal(err)
	}
	venv := t.TempDir()
	if out, err := exec.Command("python3", "-m", "venv", venv).CombinedOutput(); err != nil {
		if inCI() {
			t.Fatalf("venv: %v\n%s", err, out)
		}
		t.Skipf("venv: %v\n%s", err, out)
	}
	pip := filepath.Join(venv, "bin", "pip")
	py := filepath.Join(venv, "bin", "python")
	if out, err := exec.Command(pip, "install", "--quiet", "ldap3").CombinedOutput(); err != nil {
		if inCI() {
			t.Fatalf("pip install ldap3: %v\n%s", err, out)
		}
		t.Skipf("pip install ldap3: %v\n%s", err, out)
	}
	pw := filepath.Join(t.TempDir(), "dm.pw")
	if err := os.WriteFile(pw, []byte(env.dmPassword+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	script := filepath.Join(root, "test", "compatibility", "clients", "python", "client.py")
	args := []string{script, "--ca-file", ca,
		"--bind-dn", "cn=Directory Manager",
		"--password-file", pw,
		"--base", "dc=example,dc=test",
		"--filter", "(uid=alice)",
		"--server-name", "localhost",
	}
	if startTLS {
		args = append(args, "--url", "ldap://"+env.ldapAddr, "--starttls")
	} else {
		args = append(args, "--url", "ldaps://"+env.ldapsAddr)
	}
	cmd := exec.Command(py, args...)
	got, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("python client: %v\n%s", err, redactLogs(string(got), env.dmPassword))
	}
	if !strings.Contains(string(got), "alice") {
		t.Fatalf("python output: %s", got)
	}
}
