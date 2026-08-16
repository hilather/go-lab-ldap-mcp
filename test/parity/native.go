package parity

import (
	"context"
	"crypto/subtle"
	"crypto/tls"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	ldap "github.com/go-ldap/ldap/v3"
	"github.com/hilather/go-lab-ldap-mcp/internal/ldapserver"
	"github.com/hilather/go-lab-ldap-mcp/internal/ldapserver/store"
)

// nativeEngine runs labldapd in-process through internal/ldapserver —
// the same Options mapping cmd/labldapd/serve.go performs, driven by the
// compiled fixture scenario (store, standard schema, compiled ACI texts,
// memberof/referint plugins, compiled password policy, DM identity,
// LDAP + LDAPS + StartTLS listeners on ephemeral loopback ports).
type nativeEngine struct {
	fx        *fixture
	srv       *ldapserver.Server
	st        *store.Store
	logs      *syncLogBuf
	stop      context.CancelFunc
	done      chan error
	ldapAddr  string
	ldapsAddr string
}

// syncLogBuf is a concurrency-safe in-memory slog sink. Engine logs are
// attached to failures (contract section 5 rule 5); passwords never reach
// the log because ldapserver never logs them (asserted by its own suite).
type syncLogBuf struct {
	mu  sync.Mutex
	buf []byte
}

func (b *syncLogBuf) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.buf = append(b.buf, p...)
	return len(p), nil
}

func (b *syncLogBuf) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return string(b.buf)
}

// newNativeOptions builds ldapserver.Options from the compiled fixture —
// a direct mirror of cmd/labldapd serverOptions (kept in the test tree
// because package boundaries forbid test/parity importing cmd/labldapd).
func newNativeOptions(fx *fixture, ldapAddr, ldapsAddr string, tlsCfg *tls.Config, st ldapserver.Store, log *slog.Logger) (ldapserver.Options, error) {
	c := fx.compiled
	limits := ldapserver.DefaultLimits()
	schema, err := ldapserver.StandardSchema()
	if err != nil {
		return ldapserver.Options{}, fmt.Errorf("parity: standard schema: %w", err)
	}
	var plugins []ldapserver.Plugin
	for _, name := range c.Engine.Plugins {
		switch name {
		case "memberof":
			p, err := ldapserver.NewMemberOfPlugin(c.Engine.Suffix, c.Normalized.NestedGroups)
			if err != nil {
				return ldapserver.Options{}, fmt.Errorf("parity: memberof plugin: %w", err)
			}
			plugins = append(plugins, p)
		case "referint":
			p, err := ldapserver.NewRefIntPlugin(c.Engine.Suffix)
			if err != nil {
				return ldapserver.Options{}, fmt.Errorf("parity: referint plugin: %w", err)
			}
			plugins = append(plugins, p)
		case "account-disable":
			// Enforced unconditionally in the bind path (see serve.go).
		default:
			return ldapserver.Options{}, fmt.Errorf("parity: unknown compiled plugin %q", name)
		}
	}
	p := c.Engine.PasswordPolicy
	pp := &ldapserver.PasswordPolicy{
		MinLength:     p.MinLength,
		HistoryCount:  p.HistoryCount,
		MaxAge:        p.MaxAge,
		StorageScheme: p.StorageScheme,
	}
	if p.LockoutEnabled {
		pp.MaxFailures = p.MaxFailures
		pp.LockoutDuration = p.LockoutDuration
	}
	transport := c.Public.Spec.Transport
	dmSecret := []byte(nativeDMSecret)
	return ldapserver.Options{
		Suffix:             c.Engine.Suffix,
		LDAPAddress:        ldapAddr,
		LDAPSAddress:       ldapsAddr,
		TLSConfig:          tlsCfg,
		AllowStartTLS:      transport.StartTLS,
		AllowCleartextBind: transport.AllowCleartextBind,
		AllowAnonymousBind: transport.AllowAnonymousBind,
		PasswordPolicy:     pp,
		Limits:             limits,
		Codec:              ldapserver.NewBERCodec(ldapserver.BERCodecOptions{}),
		Store:              st,
		Schema:             schema,
		ACITexts:           fx.aciTexts(),
		NestedGroups:       c.Normalized.NestedGroups,
		Plugins:            plugins,
		DirectoryManager: ldapserver.Identity{
			DN: dmDN,
			VerifyPassword: func(password []byte) bool {
				return subtle.ConstantTimeCompare(password, dmSecret) == 1
			},
		},
		Logger: log,
	}, nil
}

// startNative boots the native engine in-process and seeds it through
// direct LDAP, exactly like the oracle path.
func startNative(t *testing.T, fx *fixture) *nativeEngine {
	t.Helper()
	st, err := store.Open(filepath.Join(t.TempDir(), "labldapd.bolt"))
	if err != nil {
		t.Fatalf("parity: native store: %v", err)
	}
	logs := &syncLogBuf{}
	log := slog.New(slog.NewTextHandler(io.Writer(logs), &slog.HandlerOptions{Level: slog.LevelDebug}))
	opts, err := newNativeOptions(fx, "127.0.0.1:0", "127.0.0.1:0", fx.tls.server, st, log)
	if err != nil {
		t.Fatalf("parity: native options: %v", err)
	}
	srv, err := ldapserver.New(opts)
	if err != nil {
		t.Fatalf("parity: native server: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	e := &nativeEngine{fx: fx, srv: srv, st: st, logs: logs, stop: cancel, done: make(chan error, 1)}
	t.Cleanup(func() {
		if t.Failed() {
			t.Logf("parity: native engine logs:\n%s", logs.String())
		}
	})
	go func() { e.done <- srv.Serve(ctx) }()

	deadline := time.Now().Add(10 * time.Second)
	for srv.LDAPAddr() == nil || srv.LDAPSAddr() == nil {
		select {
		case err := <-e.done:
			t.Fatalf("parity: native serve exited early: %v\nlogs:\n%s", err, logs.String())
		case <-time.After(5 * time.Millisecond):
		}
		if time.Now().After(deadline) {
			t.Fatalf("parity: native listeners did not bind\nlogs:\n%s", logs.String())
		}
	}
	e.ldapAddr = srv.LDAPAddr().String()
	e.ldapsAddr = srv.LDAPSAddr().String()

	dm := e.dm(t)
	seedDirectory(t, fx, dm)
	dm.Close()
	return e
}

func (e *nativeEngine) name() string     { return "native" }
func (e *nativeEngine) dmSecret() string { return nativeDMSecret }

func (e *nativeEngine) addr(ldaps bool) string {
	if ldaps {
		return e.ldapsAddr
	}
	return e.ldapAddr
}

func (e *nativeEngine) clientTLS() *tls.Config { return e.fx.tls.client }

func (e *nativeEngine) caFile(t *testing.T) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "ca.pem")
	if err := os.WriteFile(path, e.fx.tls.caPEM, 0o600); err != nil {
		t.Fatalf("parity: native CA file: %v", err)
	}
	return path
}

func (e *nativeEngine) serverName() string { return "localhost" }

func (e *nativeEngine) dial(t *testing.T, spec dialSpec) (*ldap.Conn, error) {
	t.Helper()
	clientTLS := e.fx.tls.client
	if spec.badCA {
		clientTLS = e.fx.tls.wrong
	}
	if spec.badName {
		bad := clientTLS.Clone()
		bad.ServerName = "wrong-host.example.test"
		clientTLS = bad
	}
	var conn *ldap.Conn
	var err error
	switch {
	case spec.ldaps:
		conn, err = ldap.DialURL("ldaps://"+e.ldapsAddr, ldap.DialWithTLSConfig(clientTLS))
	case spec.startTLS:
		conn, err = ldap.DialURL("ldap://" + e.ldapAddr)
		if err == nil {
			err = conn.StartTLS(clientTLS)
		}
	default:
		conn, err = ldap.DialURL("ldap://" + e.ldapAddr)
	}
	if err != nil {
		if conn != nil {
			conn.Close()
		}
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

func (e *nativeEngine) dm(t *testing.T) *ldap.Conn {
	t.Helper()
	conn, err := e.dial(t, dialSpec{ldaps: true, bindDN: dmDN, bindPass: nativeDMSecret})
	if err != nil {
		t.Fatalf("parity: native DM bind: %v\nlogs:\n%s", err, e.logs.String())
	}
	return conn
}

func (e *nativeEngine) close(t *testing.T) {
	t.Helper()
	e.stop()
	select {
	case err := <-e.done:
		if err != nil {
			t.Logf("parity: native serve exit: %v", err)
		}
	case <-time.After(10 * time.Second):
		t.Log("parity: native serve did not stop in time")
	}
	if err := e.st.Close(); err != nil {
		t.Logf("parity: native store close: %v", err)
	}
}
