//go:build integration

package dirsrv

import (
	"context"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	"github.com/hilather/go-lab-ldap-mcp/internal/directory"
	"github.com/hilather/go-lab-ldap-mcp/internal/directory/ldapclient"
)

func startLDAPClientTLS(t *testing.T) (engineDial, *TLSMaterial) {
	t.Helper()
	if itEngine(t) == EngineNative {
		n := startNative(t, runtimeYAML())
		return nativeDial(n), n.mat
	}
	mat := generateTLS(t, "localhost")
	inst := Start(t)
	inst.ImportTLS(t, mat)
	return engineDial{
		engine:     Engine389DS,
		ldapAddr:   inst.LDAPAddr,
		ldapsAddr:  inst.LDAPSAddr,
		caFile:     filepath.Join(mat.Dir, "ca", "ca.crt"),
		serverName: "localhost",
		dmPassword: inst.Password().Reveal(),
	}, mat
}

func TestLDAPClientTLSTrustAndBind(t *testing.T) {
	d, mat := startLDAPClientTLS(t)
	ca := d.caFile
	wrong := filepath.Join(t.TempDir(), "wrong.pem")
	if err := os.WriteFile(wrong, mat.WrongCAPEM, 0o600); err != nil {
		t.Fatal(err)
	}

	ok := ldapclient.Config{
		Address:      d.ldapsAddr,
		Transport:    directory.TransportLDAPS,
		CAFile:       ca,
		ServerName:   d.serverName,
		BindDN:       "cn=Directory Manager",
		BindPassword: d.secret(),
		DialTimeout:  8 * time.Second,
	}
	c, err := ldapclient.Connect(t.Context(), ok)
	if err != nil {
		t.Fatalf("correct TLS: %v", err)
	}
	_ = c.Close()
	c, err = dialReady(t, ok)
	if err != nil {
		t.Fatalf("correct TLS+bind: %v", err)
	}
	if err := c.Ping(t.Context()); err != nil {
		t.Fatalf("root dse: %v", err)
	}
	_ = c.Close()

	badCA := ok
	badCA.CAFile = wrong
	if _, err := ldapclient.Connect(t.Context(), badCA); err == nil {
		t.Fatal("wrong CA must fail closed")
	}
	badName := ok
	badName.ServerName = "not-the-server.example"
	if _, err := ldapclient.Connect(t.Context(), badName); err == nil {
		t.Fatal("wrong name must fail closed")
	}
}

func TestLDAPClientStartTLSBind(t *testing.T) {
	d, _ := startLDAPClientTLS(t)
	c, err := dialReady(t, ldapclient.Config{
		Address:      d.ldapAddr,
		Transport:    directory.TransportStartTLS,
		CAFile:       d.caFile,
		ServerName:   d.serverName,
		BindDN:       "cn=Directory Manager",
		BindPassword: d.secret(),
		DialTimeout:  8 * time.Second,
	})
	if err != nil {
		t.Fatalf("starttls bind: %v", err)
	}
	if err := c.Ping(t.Context()); err != nil {
		t.Fatalf("root dse: %v", err)
	}
	_ = c.Close()
}

func TestLDAPClientPoolRecoversAfterRestart(t *testing.T) {
	mat := generateTLS(t, "localhost")
	inst := Start(t)
	inst.ImportTLS(t, mat)
	var addr atomic.Value
	addr.Store(inst.LDAPSAddr)
	p, err := ldapclient.NewPool(ldapclient.Config{
		Address:      inst.LDAPSAddr,
		Transport:    directory.TransportLDAPS,
		CAFile:       filepath.Join(mat.Dir, "ca", "ca.crt"),
		ServerName:   "localhost",
		BindDN:       "cn=Directory Manager",
		BindPassword: inst.Password(),
		PoolSize:     2,
		DialTimeout:  8 * time.Second,
		WaitTimeout:  10 * time.Second,
		Dial: func(ctx context.Context, cfg ldapclient.Config) (*ldapclient.Conn, error) {
			cfg.Address = addr.Load().(string)
			cfg.Dial = nil
			return ldapclient.Dial(ctx, cfg)
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = p.Close() })
	ready, err := dialReady(t, ldapclient.Config{
		Address: inst.LDAPSAddr, Transport: directory.TransportLDAPS,
		CAFile: filepath.Join(mat.Dir, "ca", "ca.crt"), ServerName: "localhost",
		BindDN: "cn=Directory Manager", BindPassword: inst.Password(),
		DialTimeout: 8 * time.Second,
	})
	if err != nil {
		t.Fatalf("directory not bindable before pool: %v", err)
	}
	_ = ready.Close()
	if err := p.Do(t.Context(), func(c *ldapclient.Conn) error { return c.Ping(t.Context()) }); err != nil {
		t.Fatalf("before restart: %v", err)
	}

	if out, err := exec.Command("docker", "restart", inst.Name).CombinedOutput(); err != nil {
		t.Fatalf("docker restart: %v\n%s", err, redactLogs(string(out), inst.Password().Reveal()))
	}
	refreshHostPorts(t, inst)
	addr.Store(inst.LDAPSAddr)
	waitReady(t, inst)

	var last error
	deadline := time.Now().Add(45 * time.Second)
	for time.Now().Before(deadline) {
		last = p.Do(t.Context(), func(c *ldapclient.Conn) error { return c.Ping(t.Context()) })
		if last == nil {
			return
		}
		time.Sleep(500 * time.Millisecond)
	}
	t.Fatalf("pool did not recover after directory restart: %v", last)
}

func dialReady(t *testing.T, cfg ldapclient.Config) (*ldapclient.Conn, error) {
	t.Helper()
	var last error
	deadline := time.Now().Add(30 * time.Second)
	for time.Now().Before(deadline) {
		c, err := ldapclient.Dial(t.Context(), cfg)
		if err == nil {
			return c, nil
		}
		last = err
		time.Sleep(250 * time.Millisecond)
	}
	return nil, last
}

func refreshHostPorts(t *testing.T, inst *Instance) {
	t.Helper()
	ldapPort, err := hostPort(inst.Name, "3389/tcp")
	if err != nil {
		t.Fatal(err)
	}
	ldapsPort, err := hostPort(inst.Name, "3636/tcp")
	if err != nil {
		t.Fatal(err)
	}
	inst.LDAPAddr = net.JoinHostPort("127.0.0.1", ldapPort)
	inst.LDAPSAddr = net.JoinHostPort("127.0.0.1", ldapsPort)
}
