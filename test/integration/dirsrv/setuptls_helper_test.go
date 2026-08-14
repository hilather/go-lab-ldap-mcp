//go:build integration

package dirsrv

import (
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	"github.com/hilather/go-lab-ldap-mcp/internal/directory"
	"github.com/hilather/go-lab-ldap-mcp/internal/directory/ldapclient"
)

func TestSetupTLSHelperLDAPSAndStartTLS(t *testing.T) {
	root, err := moduleRoot()
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	cmd := exec.Command("go", "run", "./tools/setuptls", "generate", "--dir", dir, "--host", "localhost")
	cmd.Dir = root
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("generate: %v\n%s", err, redactLogs(string(out)))
	}
	if _, err := os.Stat(filepath.Join(dir, "ca.key")); err != nil {
		t.Fatal("ca.key must exist on the host")
	}

	inst := Start(t)
	copies := [][2]string{
		{filepath.Join(dir, "ca.crt"), inst.Name + ":/tmp/labldap-ca.crt"},
		{filepath.Join(dir, "directory.crt"), inst.Name + ":/tmp/labldap-server.crt"},
		{filepath.Join(dir, "directory.key"), inst.Name + ":/tmp/labldap-server.key"},
	}
	for _, c := range copies {
		if out, err := exec.Command("docker", "cp", c[0], c[1]).CombinedOutput(); err != nil {
			t.Fatalf("docker cp: %v\n%s", err, redactLogs(string(out), inst.password))
		}
	}
	for _, args := range [][]string{
		{"dsctl", "localhost", "tls", "import-ca", "/tmp/labldap-ca.crt", "LabLDAP-Lab-CA"},
		{"dsctl", "localhost", "tls", "import-server-key-cert", "/tmp/labldap-server.crt", "/tmp/labldap-server.key"},
	} {
		if out, err := exec.Command("docker", append([]string{"exec", inst.Name}, args...)...).CombinedOutput(); err != nil {
			t.Fatalf("%s: %v\n%s", args[0], err, redactLogs(string(out), inst.password))
		}
	}
	if out, err := exec.Command("docker", "restart", inst.Name).CombinedOutput(); err != nil {
		t.Fatalf("restart: %v\n%s", err, redactLogs(string(out), inst.password))
	}
	ldapPort, err := hostPort(inst.Name, "3389/tcp")
	if err != nil {
		t.Fatal(err)
	}
	ldapsPort, err := hostPort(inst.Name, "3636/tcp")
	if err != nil {
		t.Fatal(err)
	}
	inst.LDAPAddr = netJoin(ldapPort)
	inst.LDAPSAddr = netJoin(ldapsPort)
	waitReady(t, inst)

	ca := filepath.Join(dir, "ca.crt")
	ok := ldapclient.Config{
		Address:      inst.LDAPSAddr,
		Transport:    directory.TransportLDAPS,
		CAFile:       ca,
		ServerName:   "localhost",
		BindDN:       "cn=Directory Manager",
		BindPassword: inst.Password(),
		DialTimeout:  8 * time.Second,
	}
	c, err := ldapclient.Connect(t.Context(), ok)
	if err != nil {
		t.Fatalf("LDAPS with helper CA: %v", err)
	}
	_ = c.Close()

	badName := ok
	badName.ServerName = "not-the-server.example"
	if _, err := ldapclient.Connect(t.Context(), badName); err == nil {
		t.Fatal("wrong SAN must fail")
	}

	st, err := ldapclient.Connect(t.Context(), ldapclient.Config{
		Address:      inst.LDAPAddr,
		Transport:    directory.TransportStartTLS,
		CAFile:       ca,
		ServerName:   "localhost",
		BindDN:       "cn=Directory Manager",
		BindPassword: inst.Password(),
		DialTimeout:  8 * time.Second,
	})
	if err != nil {
		t.Fatalf("StartTLS with helper CA: %v", err)
	}
	if err := st.Ping(t.Context()); err != nil {
		t.Fatalf("StartTLS ping: %v", err)
	}
	_ = st.Close()
}

func netJoin(port string) string {
	return "127.0.0.1:" + port
}
