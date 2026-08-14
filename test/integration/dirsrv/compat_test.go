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

func TestCompatibilityLDAPClients(t *testing.T) {
	inst := Start(t)
	_, guest := stageSeedApply(t, inst, seedYAML("merge"), seedCanary)
	out, err := execApply(t, inst, guest, nil)
	if err != nil {
		t.Fatalf("apply: %v\n%s", err, redactLogs(out, seedCanary, inst.password))
	}
	mat := generateTLS(t, "localhost")
	inst.ImportTLS(t, mat)
	ca := filepath.Join(mat.Dir, "ca", "ca.crt")

	recordClientVersions(t)

	t.Run("ldapsearch_ldaps", func(t *testing.T) {
		requireHostTool(t, "ldapsearch")
		pw := writePW(t, inst.Password().Reveal())
		cmd := exec.Command("ldapsearch", "-x", "-LLL",
			"-H", "ldaps://"+inst.LDAPSAddr,
			"-o", "tls_reqcert=demand",
			"-o", "tls_cacert="+ca,
			"-D", "cn=Directory Manager", "-y", pw,
			"-b", "dc=example,dc=test", "-s", "sub", "(uid=alice)", "uid", "memberOf")
		got, err := cmd.CombinedOutput()
		if err != nil {
			t.Fatalf("%v\n%s", err, redactLogs(string(got), inst.password, seedCanary))
		}
		if !strings.Contains(string(got), "uid: alice") {
			t.Fatalf("missing alice:\n%s", got)
		}
	})

	t.Run("ldapwhoami_starttls", func(t *testing.T) {
		requireHostTool(t, "ldapwhoami")
		pw := writePW(t, seedCanary)
		cmd := exec.Command("ldapwhoami", "-x", "-ZZ",
			"-H", "ldap://"+inst.LDAPAddr,
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

	t.Run("ldapsearch_paging", func(t *testing.T) {
		requireHostTool(t, "ldapsearch")
		pw := writePW(t, inst.Password().Reveal())
		cmd := exec.Command("ldapsearch", "-x", "-LLL",
			"-H", "ldaps://"+inst.LDAPSAddr,
			"-o", "tls_reqcert=demand",
			"-o", "tls_cacert="+ca,
			"-D", "cn=Directory Manager", "-y", pw,
			"-E", "pr=2/noprompt",
			"-b", "dc=example,dc=test", "(objectClass=inetOrgPerson)", "uid")
		got, err := cmd.CombinedOutput()
		if err != nil {
			t.Fatalf("%v\n%s", err, redactLogs(string(got), inst.password))
		}
		if !strings.Contains(string(got), "uid: alice") {
			t.Fatalf("page missing alice:\n%s", got)
		}
	})

	t.Run("password_modify_and_rebind", func(t *testing.T) {
		requireHostTool(t, "ldapmodify")
		neu := seedCanary + "X"
		pw := writePW(t, inst.Password().Reveal())
		replacePassword := func(value string) {
			t.Helper()
			ldif := "dn: uid=alice,ou=people,dc=example,dc=test\nchangetype: modify\nreplace: userPassword\nuserPassword: " + value + "\n"
			cmd := exec.Command("ldapmodify", "-x",
				"-H", "ldaps://"+inst.LDAPSAddr,
				"-o", "tls_reqcert=demand",
				"-o", "tls_cacert="+ca,
				"-D", "cn=Directory Manager", "-y", pw)
			cmd.Stdin = strings.NewReader(ldif)
			if out, err := cmd.CombinedOutput(); err != nil {
				t.Fatalf("ldapmodify: %v\n%s", err, redactLogs(string(out), inst.password, seedCanary, neu))
			}
		}
		replacePassword(neu)
		if err := userBind(t, inst, "uid=alice,ou=people,dc=example,dc=test", neu); err != nil {
			t.Fatalf("rebind: %v", err)
		}
		replacePassword(seedCanary)
	})

	t.Run("go_independent", func(t *testing.T) {
		who, dns, err := goindep.SearchWhoami(goindep.Config{
			URL:        "ldaps://" + inst.LDAPSAddr,
			CAFile:     ca,
			ServerName: "localhost",
			BindDN:     "cn=Directory Manager",
			Password:   inst.Password().Reveal(),
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
			URL:        "ldap://" + inst.LDAPAddr,
			StartTLS:   true,
			CAFile:     ca,
			ServerName: "localhost",
			BindDN:     "cn=Directory Manager",
			Password:   inst.Password().Reveal(),
			BaseDN:     "dc=example,dc=test",
			Filter:     "(uid=alice)",
			PageSize:   2,
		})
		if err != nil {
			t.Fatalf("go starttls: %v", err)
		}
		_, _, err = goindep.SearchWhoami(goindep.Config{
			URL:      "ldap://" + inst.LDAPAddr,
			BindDN:   "cn=Directory Manager",
			Password: inst.Password().Reveal(),
			BaseDN:   "dc=example,dc=test",
			Filter:   "(uid=alice)",
		})
		if err == nil {
			t.Fatal("cleartext LDAP bind must fail when allowCleartextBind is false")
		}
	})

	t.Run("python_ldap3", func(t *testing.T) {
		runPythonClient(t, inst, ca, false)
		runPythonClient(t, inst, ca, true)
	})

	t.Run("aci_alice_read_no_config", func(t *testing.T) {
		cmd := exec.Command("docker", "exec", inst.Name,
			"ldapsearch", "-x", "-H", "ldaps://127.0.0.1:3636", "-o", "tls_reqcert=never",
			"-D", "uid=alice,ou=people,dc=example,dc=test", "-w", seedCanary,
			"-b", "cn=config", "-s", "base", "dn")
		out, err := cmd.CombinedOutput()
		if err == nil && strings.Contains(string(out), "dn: cn=config") {
			t.Fatalf("alice must not read cn=config:\n%s", out)
		}
		staff := ldapSearch(t, inst, "cn=staff,ou=groups,dc=example,dc=test", "member")
		if !strings.Contains(staff, "uid=alice") {
			t.Fatalf("membership missing:\n%s", staff)
		}
	})

	t.Run("anonymous_denied", func(t *testing.T) {
		requireHostTool(t, "ldapsearch")
		cmd := exec.Command("ldapsearch", "-x", "-LLL",
			"-H", "ldaps://"+inst.LDAPSAddr,
			"-o", "tls_reqcert=demand",
			"-o", "tls_cacert="+ca,
			"-b", "dc=example,dc=test", "(uid=alice)", "uid")
		got, err := cmd.CombinedOutput()
		if err == nil && strings.Contains(string(got), "uid: alice") {
			t.Fatalf("anonymous search must not return alice:\n%s", got)
		}
	})
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

func runPythonClient(t *testing.T, inst *Instance, ca string, startTLS bool) {
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
	if err := os.WriteFile(pw, []byte(inst.Password().Reveal()+"\n"), 0o600); err != nil {
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
		args = append(args, "--url", "ldap://"+inst.LDAPAddr, "--starttls")
	} else {
		args = append(args, "--url", "ldaps://"+inst.LDAPSAddr)
	}
	cmd := exec.Command(py, args...)
	got, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("python client: %v\n%s", err, redactLogs(string(got), inst.password))
	}
	if !strings.Contains(string(got), "alice") {
		t.Fatalf("python output: %s", got)
	}
}
