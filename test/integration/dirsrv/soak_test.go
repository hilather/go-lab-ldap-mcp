//go:build integration

package dirsrv

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"sync"
	"testing"
	"time"

	ldap "github.com/go-ldap/ldap/v3"
	"github.com/hilather/go-lab-ldap-mcp/internal/config"
	"github.com/hilather/go-lab-ldap-mcp/internal/directory"
	"github.com/hilather/go-lab-ldap-mcp/internal/directory/ldapclient"
	"github.com/hilather/go-lab-ldap-mcp/test/compatibility/goindep"
)

func TestSoakSmallProfile(t *testing.T) {
	inst := Start(t)
	_, guest := stageSeedApply(t, inst, seedYAML("merge"), seedCanary)
	if out, err := execApply(t, inst, guest, nil); err != nil {
		t.Fatalf("apply: %v\n%s", err, redactLogs(out, seedCanary, inst.password))
	}
	mat := generateTLS(t, "localhost")
	inst.ImportTLS(t, mat)
	ca := filepath.Join(mat.Dir, "ca", "ca.crt")
	const extra = 19
	addPeople(t, inst, extra)

	start := time.Now()
	who, dns, err := goindep.SearchWhoami(goindep.Config{
		URL:        "ldaps://" + inst.LDAPSAddr,
		CAFile:     ca,
		ServerName: "localhost",
		BindDN:     "cn=Directory Manager",
		Password:   inst.Password().Reveal(),
		BaseDN:     "dc=example,dc=test",
		Filter:     "(objectClass=inetOrgPerson)",
		PageSize:   10,
	})
	elapsed := time.Since(start)
	if err != nil {
		t.Fatal(err)
	}
	if len(dns) < extra {
		t.Fatalf("whoami=%q listed %d, want >= %d", who, len(dns), extra)
	}
	t.Logf("first paged search users=%d duration=%s", len(dns), elapsed)

	p, err := ldapclient.NewPool(ldapclient.Config{
		Address:      inst.LDAPSAddr,
		Transport:    directory.TransportLDAPS,
		CAFile:       ca,
		ServerName:   "localhost",
		BindDN:       "cn=Directory Manager",
		BindPassword: inst.Password(),
		PoolSize:     4,
		DialTimeout:  8 * time.Second,
		WaitTimeout:  8 * time.Second,
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = p.Close() })

	runtime.GC()
	baseG := runtime.NumGoroutine()
	baseFD := fdCount(t)
	var wg sync.WaitGroup
	stop := time.Now().Add(400 * time.Millisecond)
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for time.Now().Before(stop) {
				err := p.Do(t.Context(), func(c *ldapclient.Conn) error { return c.Ping(t.Context()) })
				if err != nil {
					t.Errorf("ping: %v", err)
					return
				}
			}
		}()
	}
	wg.Wait()
	if err := p.Shutdown(t.Context()); err != nil {
		t.Fatal(err)
	}
	time.Sleep(50 * time.Millisecond)
	runtime.GC()
	if g := runtime.NumGoroutine(); g > baseG+16 {
		t.Fatalf("goroutine growth: before %d after %d", baseG, g)
	}
	if fd := fdCount(t); fd > baseFD+16 {
		t.Fatalf("fd growth: before %d after %d", baseFD, fd)
	}
	st := p.Stats()
	if st.Active > 4 {
		t.Fatalf("pool active unbounded: %+v", st)
	}
}

func TestSoakMediumProfile(t *testing.T) {
	if os.Getenv("LABLDAP_SOAK_MEDIUM") != "1" {
		t.Skip("medium profile residual: set LABLDAP_SOAK_MEDIUM=1 to run ~10k/1k generate+compile")
	}
	root, err := moduleRoot()
	if err != nil {
		t.Fatal(err)
	}
	out := filepath.Join(t.TempDir(), "medium.yaml")
	cmd := exec.Command("go", "run", "./tools/dataset",
		"--users", "10000", "--groups", "1000",
		"--password-file", "secrets/user-alice",
		"--out", out)
	cmd.Dir = root
	if raw, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("dataset: %v\n%s", err, raw)
	}
	src, err := os.ReadFile(out)
	if err != nil {
		t.Fatal(err)
	}
	start := time.Now()
	if _, err := config.Compile(t.Context(), src, out, config.LoadOptions{Caller: config.CallerControl, Secrets: config.DirSecretResolver(filepath.Join(root, "config", "examples"))}); err != nil {
		t.Fatalf("compile medium: %v", err)
	}
	t.Logf("compiled 10000/1000 in %s", time.Since(start))
}

func TestDatasetSmallCompiles(t *testing.T) {
	root, err := moduleRoot()
	if err != nil {
		t.Fatal(err)
	}
	out := filepath.Join(t.TempDir(), "small.yaml")
	cmd := exec.Command("go", "run", "./tools/dataset", "--users", "8", "--groups", "2",
		"--password-file", "secrets/user-alice", "--out", out)
	cmd.Dir = root
	if raw, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("dataset: %v\n%s", err, raw)
	}
	src, err := os.ReadFile(out)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := config.Compile(t.Context(), src, out, config.LoadOptions{
		Caller:  config.CallerControl,
		Secrets: config.DirSecretResolver(filepath.Join(root, "config", "examples")),
	}); err != nil {
		t.Fatal(err)
	}
}

func addPeople(t *testing.T, inst *Instance, n int) {
	t.Helper()
	d := inst.Dial(t)
	conn := d.dmMust(t)
	defer conn.Close()
	for i := 1; i <= n; i++ {
		uid := fmt.Sprintf("u%03d", i)
		req := ldap.NewAddRequest("uid="+uid+",ou=people,dc=example,dc=test", nil)
		req.Attribute("objectClass", []string{"inetOrgPerson"})
		req.Attribute("uid", []string{uid})
		req.Attribute("cn", []string{uid})
		req.Attribute("sn", []string{"soak"})
		if err := conn.Add(req); err != nil && !ldap.IsErrorWithCode(err, ldap.LDAPResultEntryAlreadyExists) {
			t.Fatalf("ldapadd people: %v", err)
		}
	}
}

func fdCount(t *testing.T) int {
	t.Helper()
	ents, err := os.ReadDir("/proc/self/fd")
	if err != nil {
		t.Skip("no /proc/self/fd")
	}
	return len(ents)
}
