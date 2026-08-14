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
	imp := exec.Command("go", "run", "./tools/setuptls", "import", "--dir", dir, "--container", inst.Name)
	imp.Dir = root
	if out, err := imp.CombinedOutput(); err != nil {
		t.Fatalf("import: %v\n%s", err, redactLogs(string(out), inst.password))
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
