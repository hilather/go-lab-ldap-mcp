//go:build integration

package dirsrv

import (
	"bytes"
	"context"
	"crypto/subtle"
	"crypto/tls"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/hilather/go-lab-ldap-mcp/internal/bootstrap"
	"github.com/hilather/go-lab-ldap-mcp/internal/config"
	"github.com/hilather/go-lab-ldap-mcp/internal/directory/ds389"
	"github.com/hilather/go-lab-ldap-mcp/internal/ldapserver"
	"github.com/hilather/go-lab-ldap-mcp/internal/ldapserver/store"
	"github.com/hilather/go-lab-ldap-mcp/internal/observability"
)

// nativeInstance is the T-148 native engine fixture: an in-process
// labldapd-equivalent server (internal/ldapserver + bbolt store) on
// loopback ephemeral ports. It is hermetic — no Docker, no Compose — and
// carries the same tree, seed users, and compiled runtime ACI set as the
// 389 container after `labldap-bootstrap apply`.
type nativeInstance struct {
	LDAPAddr   string
	LDAPSAddr  string
	CAFile     string
	ServerName string

	dmPassword string
	srv        *ldapserver.Server
	logs       *bytes.Buffer
	// mat is the TLS material the fixture serves (test CA + server cert);
	// trust assertions reuse it instead of a dsctl-style import (D2).
	mat *TLSMaterial
}

// Password returns the fixture Directory Manager password (random per run,
// held only in memory — never written to a file the suite logs).
func (n *nativeInstance) Password() observability.Secret { return observability.Secret(n.dmPassword) }

// startNative builds the native fixture from a scenario YAML: compile with
// the bootstrap caller, wire the compiled engine plan into ldapserver
// options exactly as cmd/labldapd does (serverOptions), then apply the data
// plane (tree, runtime ACIs, seed) through the shared LDAP-as-DM
// reconcilers (ADR-0009 decision 12).
func startNative(t *testing.T, yaml string) *nativeInstance {
	t.Helper()
	yaml = withITEngine(yaml)

	// TLS material is the same test CA the 389 run imports via dsctl;
	// clients trust ca.crt and verify the "localhost" name on both engines.
	mat := generateTLS(t, "localhost")
	dir := t.TempDir()
	sec := filepath.Join(dir, "secrets")
	if err := os.Mkdir(sec, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(sec, "runtime-ldap"), []byte("runtime-secret\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(sec, "user-alice"), []byte(seedCanary+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	cfgPath := filepath.Join(dir, "lab.yaml")
	if err := os.WriteFile(cfgPath, []byte(yaml), 0o600); err != nil {
		t.Fatal(err)
	}
	compiled, err := config.Compile(t.Context(), []byte(yaml), cfgPath, config.LoadOptions{
		Caller:  config.CallerBootstrap,
		Secrets: config.DirSecretResolver(dir),
	})
	if err != nil {
		t.Fatalf("compile native scenario: %v", err)
	}

	cert, err := tls.LoadX509KeyPair(filepath.Join(mat.Dir, "server.crt"), filepath.Join(mat.Dir, "server.key"))
	if err != nil {
		t.Fatalf("native TLS material: %v", err)
	}
	dmPassword := randomSecret()
	dmWant := []byte(dmPassword)
	logs := &bytes.Buffer{}
	log := observability.NewLogger(logs, observability.FormatFromEnv(), observability.CurrentBuild("labldapd"))

	st, err := store.Open(filepath.Join(dir, "labldapd.bolt"))
	if err != nil {
		t.Fatalf("native store: %v", err)
	}

	// Engine plan -> ldapserver.Options, mirroring cmd/labldapd
	// (serverOptions, enginePlugins, passwordPolicy). Keep the mapping in
	// sync with the daemon; drift here is a fixture bug, not a Delta.
	n := compiled.Normalized
	plugins := []ldapserver.Plugin{}
	for _, name := range compiled.Engine.Plugins {
		switch name {
		case "memberof":
			p, err := ldapserver.NewMemberOfPlugin(compiled.Engine.Suffix, n.NestedGroups, n.AdditionalSuffixStrings()...)
			if err != nil {
				t.Fatalf("native memberof: %v", err)
			}
			plugins = append(plugins, p)
		case "referint":
			p, err := ldapserver.NewRefIntPlugin(compiled.Engine.Suffix, n.AdditionalSuffixStrings()...)
			if err != nil {
				t.Fatalf("native referint: %v", err)
			}
			plugins = append(plugins, p)
		case "account-disable":
			// Enforced unconditionally in the native bind path; no plugin.
		default:
			t.Fatalf("native fixture: unknown compiled plugin %q", name)
		}
	}
	policy := compiled.Engine.PasswordPolicy
	pp := &ldapserver.PasswordPolicy{
		MinLength:     policy.MinLength,
		HistoryCount:  policy.HistoryCount,
		MaxAge:        policy.MaxAge,
		StorageScheme: policy.StorageScheme,
	}
	if policy.LockoutEnabled {
		pp.MaxFailures = policy.MaxFailures
		pp.LockoutDuration = policy.LockoutDuration
	}
	aciTexts := make([]string, 0, len(compiled.Data.ACIs))
	for _, a := range compiled.Data.ACIs {
		aciTexts = append(aciTexts, a.Text)
	}
	schema, err := ldapserver.StandardSchema()
	if err != nil {
		t.Fatalf("native schema: %v", err)
	}
	transport := compiled.Public.Spec.Transport
	srv, err := ldapserver.New(ldapserver.Options{
		Suffix:             compiled.Engine.Suffix,
		AdditionalSuffixes: n.AdditionalSuffixStrings(),
		LDAPAddress:        "127.0.0.1:0",
		LDAPSAddress:       "127.0.0.1:0",
		TLSConfig:          &tls.Config{Certificates: []tls.Certificate{cert}},
		AllowStartTLS:      true,
		AllowCleartextBind: transport.AllowCleartextBind,
		AllowAnonymousBind: transport.AllowAnonymousBind,
		PasswordPolicy:     pp,
		Limits:             ldapserver.DefaultLimits(),
		Codec:              ldapserver.NewBERCodec(ldapserver.BERCodecOptions{}),
		Store:              st,
		Schema:             schema,
		ACITexts:           aciTexts,
		Plugins:            plugins,
		DirectoryManager: ldapserver.Identity{
			DN: "cn=Directory Manager",
			VerifyPassword: func(password []byte) bool {
				return subtle.ConstantTimeCompare(password, dmWant) == 1
			},
		},
		Logger: log,
	})
	if err != nil {
		t.Fatalf("native server: %v", err)
	}

	serveCtx, stop := context.WithCancel(context.Background())
	serveDone := make(chan struct{})
	inst := &nativeInstance{
		CAFile:     filepath.Join(mat.Dir, "ca", "ca.crt"),
		ServerName: "localhost",
		dmPassword: dmPassword,
		srv:        srv,
		logs:       logs,
		mat:        mat,
	}
	go func() {
		_ = srv.Serve(serveCtx)
		close(serveDone)
	}()
	t.Cleanup(func() {
		stop()
		<-serveDone
		if err := srv.Close(); err != nil {
			t.Errorf("native store close: %v", err)
		}
		if t.Failed() {
			t.Logf("native engine logs (redacted):\n%s", redactLogs(logs.String(), dmPassword, seedCanary))
		}
	})
	waitNativeBound(t, srv)

	inst.LDAPAddr = srv.LDAPAddr().String()
	inst.LDAPSAddr = srv.LDAPSAddr().String()
	inst.seed(t, compiled)
	return inst
}

func waitNativeBound(t *testing.T, srv *ldapserver.Server) {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		if srv.LDAPAddr() != nil && srv.LDAPSAddr() != nil {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatal("native listeners did not bind in time")
}

// seed applies the compiled data plane (tree, ACIs, users, groups) through
// ds389.Engine — the bootstrap LDAP-as-DM implementation both engines share
// — over LDAPS against the native listener. This is the Contract-applicable
// core of the T-043 observed seed flow (C5 tree shape, C3 seed bind, C7
// membership); the dsconf read-backs around it are 389-only (D2/D5).
func (n *nativeInstance) seed(t *testing.T, compiled *config.Compiled) {
	t.Helper()
	nrm := compiled.Normalized
	treq := bootstrap.TreeRequest{
		Suffix:             compiled.Engine.Suffix,
		AdditionalSuffixes: nrm.AdditionalSuffixStrings(),
		PeopleDN:           nrm.PeopleDN.String(),
		GroupsDN:           nrm.GroupsDN.String(),
		RuntimeDN:          nrm.Runtime.DN,
		RuntimePassword:    nrm.Runtime.Password.Value,
		DMPassword:         n.Password(),
		LDAPURL:            "ldaps://" + n.LDAPSAddr,
		CAFile:             n.CAFile,
		Host:               n.ServerName,
		Write:              true,
	}
	eng := ds389.Engine{}
	if _, err := eng.ReconcileTree(t.Context(), treq); err != nil {
		t.Fatalf("native tree apply: %v", err)
	}
	if _, err := eng.ReconcileACIs(t.Context(), bootstrap.ACIRequest{TreeRequest: treq, ACIs: compiled.Data.ACIs}); err != nil {
		t.Fatalf("native ACI apply: %v", err)
	}
	res, err := eng.ReconcileSeed(t.Context(), bootstrap.SeedRequest{
		TreeRequest: treq,
		Users:       nrm.Users,
		Groups:      nrm.Groups,
		StartupMode: nrm.StartupMode,
	})
	if err != nil {
		t.Fatalf("native seed apply: %v", err)
	}
	if len(res.Created) == 0 {
		t.Fatalf("native seed created nothing: %+v", res)
	}
}
