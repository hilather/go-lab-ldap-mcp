package main

import (
	"context"
	"crypto/subtle"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	"github.com/hilather/go-lab-ldap-mcp/internal/apperr"
	"github.com/hilather/go-lab-ldap-mcp/internal/config"
	"github.com/hilather/go-lab-ldap-mcp/internal/config/v1alpha1"
	"github.com/hilather/go-lab-ldap-mcp/internal/ldapserver"
	"github.com/hilather/go-lab-ldap-mcp/internal/ldapserver/store"
	"github.com/hilather/go-lab-ldap-mcp/internal/observability"
)

// Flag defaults. Listener and health hosts are loopback unless an
// explicit address says otherwise (ADR-0009 decision 4); the deploy
// overlay passes 0.0.0.0 in-container and keeps host publishes loopback.
const (
	defaultDataDir      = "/data"
	defaultLDAPListen   = "127.0.0.1:3389"
	defaultLDAPSListen  = "127.0.0.1:3636"
	defaultHealthListen = "127.0.0.1:8389"
	// storeFileName is the bbolt database file inside the data directory
	// (deploy/docker/labldapd-image-contract.md).
	storeFileName = "labldapd.bolt"
	// directoryManagerDN is the native root identity (ADR-0009 decision 13,
	// default value). Bootstrap binds it as defaultBindDN; no scenario
	// field renames it yet (tracked for T-146 documentation).
	directoryManagerDN = "cn=Directory Manager"
)

type serveFlags struct {
	configPath     string
	dataDir        string
	listen         string
	ldapsListen    string
	tlsCertFile    string
	tlsKeyFile     string
	dmPasswordFile string
	healthListen   string
}

func defaultServeFlags() serveFlags {
	return serveFlags{
		dataDir:      defaultDataDir,
		listen:       defaultLDAPListen,
		ldapsListen:  defaultLDAPSListen,
		healthListen: defaultHealthListen,
	}
}

var errServeHelp = fmt.Errorf("help")

// parseServeFlags mirrors the hand-rolled style of cmd/labldap so the
// daemons read the same. Listener flags accept an explicit empty value
// (--listen=) to disable that listener.
func parseServeFlags(args []string) (serveFlags, error) {
	f := defaultServeFlags()
	next := func(i *int, name string) (string, error) {
		if *i+1 >= len(args) {
			return "", fmt.Errorf("%s requires a value", name)
		}
		*i++
		return args[*i], nil
	}
	var err error
	for i := 0; i < len(args); i++ {
		a := args[i]
		switch {
		case a == "--config":
			if f.configPath, err = next(&i, "--config"); err != nil {
				return f, err
			}
		case a == "--data-dir":
			if f.dataDir, err = next(&i, "--data-dir"); err != nil {
				return f, err
			}
		case a == "--listen":
			if f.listen, err = next(&i, "--listen"); err != nil {
				return f, err
			}
		case a == "--ldaps-listen":
			if f.ldapsListen, err = next(&i, "--ldaps-listen"); err != nil {
				return f, err
			}
		case a == "--tls-cert-file":
			if f.tlsCertFile, err = next(&i, "--tls-cert-file"); err != nil {
				return f, err
			}
		case a == "--tls-key-file":
			if f.tlsKeyFile, err = next(&i, "--tls-key-file"); err != nil {
				return f, err
			}
		case a == "--directory-manager-password-file":
			if f.dmPasswordFile, err = next(&i, "--directory-manager-password-file"); err != nil {
				return f, err
			}
		case a == "--health-listen":
			if f.healthListen, err = next(&i, "--health-listen"); err != nil {
				return f, err
			}
		case hasFlagValue(a, "--config"):
			f.configPath = flagValue(a)
		case hasFlagValue(a, "--data-dir"):
			f.dataDir = flagValue(a)
		case hasFlagValue(a, "--listen"):
			f.listen = flagValue(a)
		case hasFlagValue(a, "--ldaps-listen"):
			f.ldapsListen = flagValue(a)
		case hasFlagValue(a, "--tls-cert-file"):
			f.tlsCertFile = flagValue(a)
		case hasFlagValue(a, "--tls-key-file"):
			f.tlsKeyFile = flagValue(a)
		case hasFlagValue(a, "--directory-manager-password-file"):
			f.dmPasswordFile = flagValue(a)
		case hasFlagValue(a, "--health-listen"):
			f.healthListen = flagValue(a)
		case a == "-h" || a == "--help":
			return f, errServeHelp
		default:
			return f, fmt.Errorf("unknown flag %q", a)
		}
	}
	return f, nil
}

func hasFlagValue(arg, name string) bool {
	return len(arg) > len(name) && arg[:len(name)] == name && arg[len(name)] == '='
}

func flagValue(arg string) string {
	for i := 0; i < len(arg); i++ {
		if arg[i] == '=' {
			return arg[i+1:]
		}
	}
	return ""
}

func runServe(args []string, stdout, stderr io.Writer) int {
	flags, err := parseServeFlags(args)
	if err != nil {
		if errors.Is(err, errServeHelp) {
			fmt.Fprint(stdout, serveUsage)
			return 0
		}
		fmt.Fprintf(stderr, "labldapd serve: %v\n", err)
		return 2
	}
	log := observability.NewLogger(stderr, observability.FormatFromEnv(), observability.CurrentBuild("labldapd"))
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	if err := serve(ctx, flags, log); err != nil {
		printServeError(stderr, err)
		return 1
	}
	return 0
}

// printServeError mirrors cmd/labldap's config-error shape: the public
// message plus one line per structured field. Secrets are never printed —
// apperr messages are redacted by contract and no serve error carries
// credential material.
func printServeError(w io.Writer, err error) {
	var e *apperr.Error
	if errors.As(err, &e) {
		fmt.Fprintf(w, "labldapd serve: %s\n", e.PublicMessage())
		for _, f := range e.Fields() {
			fmt.Fprintf(w, "  %s: %s (%s)\n", f.Path, f.Message, f.Code)
		}
		return
	}
	fmt.Fprintf(w, "labldapd serve: %v\n", err)
}

// serve is the testable body of runServe: build everything, serve until
// ctx ends, shut down gracefully.
func serve(ctx context.Context, f serveFlags, log *slog.Logger) error {
	d, err := startDaemon(ctx, f, log)
	if err != nil {
		return err
	}
	return d.block(ctx, log)
}

// daemon is one running labldapd: the LDAP server, its store, and the
// loopback health listener. serveDone closes when the LDAP Serve loop
// returns; exitErr is written before that close, so readers that observe
// serveDone may read it without a data race.
type daemon struct {
	server    *ldapserver.Server
	store     *store.Store
	health    *http.Server
	healthLn  net.Listener
	wantLDAP  bool
	wantLDAPS bool
	stopServe context.CancelFunc
	serveDone chan struct{}
	exitErr   error
	healthErr chan error
}

// startDaemon loads the scenario, opens the store, self-applies the engine
// plan, and binds all listeners. It returns only after the directory
// listeners are bound, so callers (and Compose healthchecks) can rely on
// the process serving once startup succeeds. Any failure before this point
// leaves no listener behind.
func startDaemon(ctx context.Context, f serveFlags, log *slog.Logger) (*daemon, error) {
	if f.configPath == "" {
		return nil, configFieldErr("config", "required", "--config is required")
	}
	if f.dmPasswordFile == "" {
		return nil, configFieldErr("directoryManager.passwordFile", "required", "--directory-manager-password-file is required")
	}
	if f.listen == "" && f.ldapsListen == "" {
		return nil, configFieldErr("listen", "required", "at least one of --listen or --ldaps-listen must be set")
	}

	compiled, err := compileEnginePlan(ctx, f.configPath)
	if err != nil {
		return nil, err
	}

	// The Directory Manager secret is resolved before any listener exists
	// (acceptance: a missing DM file must exit non-zero without protocol
	// start). The verifier closes over the bytes; the value never appears
	// in logs or dumps.
	dmSecret, err := config.FileSecretResolver().Resolve(ctx, "directory-manager-password-file", f.dmPasswordFile)
	if err != nil {
		return nil, err
	}
	dm := dmIdentity([]byte(dmSecret.Value.Reveal()))

	tlsCfg, err := serverTLSConfig(f, compiled)
	if err != nil {
		return nil, err
	}

	if err := os.MkdirAll(f.dataDir, 0o700); err != nil {
		return nil, fmt.Errorf("labldapd: create data directory: %w", err)
	}
	st, err := store.Open(filepath.Join(f.dataDir, storeFileName))
	if err != nil {
		return nil, err
	}
	ok := false
	defer func() {
		if !ok {
			_ = st.Close()
		}
	}()

	// Self-apply the engine plan: publish the applied suffix/policy/plugin
	// state for bootstrap read-back (ADR-0009 decisions 11-12), then wire
	// the same values into the server.
	if err := publishEngineState(ctx, st, engineStateEntry(compiled)); err != nil {
		return nil, fmt.Errorf("labldapd: publish engine state: %w", err)
	}
	plugins, err := enginePlugins(compiled)
	if err != nil {
		return nil, err
	}
	log.Info("engine plan applied",
		"engine", engineName,
		"suffix", compiled.Engine.Suffix,
		"plugins", compiled.Engine.Plugins,
		"storageScheme", compiled.Engine.PasswordPolicy.StorageScheme)

	opts, err := serverOptions(compiled, f, tlsCfg, dm, plugins, st, log)
	if err != nil {
		return nil, err
	}
	srv, err := ldapserver.New(opts)
	if err != nil {
		return nil, err
	}

	serveCtx, stopServe := context.WithCancel(ctx)
	d := &daemon{
		server:    srv,
		store:     st,
		wantLDAP:  opts.LDAPAddress != "",
		wantLDAPS: opts.LDAPSAddress != "",
		stopServe: stopServe,
		serveDone: make(chan struct{}),
	}
	go func() {
		d.exitErr = srv.Serve(serveCtx)
		close(d.serveDone)
	}()
	if err := d.waitBound(ctx); err != nil {
		stopServe()
		<-d.serveDone
		return nil, err
	}
	log.Info("directory listeners bound", "ldap", srv.LDAPAddr(), "ldaps", srv.LDAPSAddr())

	if f.healthListen != "" {
		if err := d.startHealth(f.healthListen); err != nil {
			stopServe()
			<-d.serveDone
			return nil, err
		}
		log.Info("health listener bound", "addr", d.healthLn.Addr())
	}
	ok = true
	return d, nil
}

// compileEnginePlan reads and compiles the scenario and enforces that this
// daemon is the selected engine. The daemon compiles with no secret
// resolver: it never reads user, runtime, or token secret files — the data
// plane (and its secrets) belongs to labldap-bootstrap (ADR-0009 decision
// 12). Only the engine plan is consumed here.
func compileEnginePlan(ctx context.Context, path string) (*config.Compiled, error) {
	src, err := os.ReadFile(path)
	if err != nil {
		return nil, apperr.New(apperr.CodeConfiguration, "configuration file unreadable").
			WithField(apperr.Field{Path: "config", Code: "unreadable", Message: "path could not be read"})
	}
	compiled, err := config.Compile(ctx, src, path, config.LoadOptions{Caller: config.CallerCLI})
	if err != nil {
		return nil, err
	}
	if compiled.Normalized.Engine != v1alpha1.EngineNative {
		return nil, configFieldErr("spec.directory.engine", "engine_not_native",
			"labldapd serves only engine: native (the 389ds engine is the dserv container, not this daemon)")
	}
	return compiled, nil
}

// dmIdentity builds the Directory Manager identity with a constant-time
// verifier. The secret bytes live only inside this closure.
func dmIdentity(secret []byte) ldapserver.Identity {
	want := append([]byte(nil), secret...)
	return ldapserver.Identity{
		DN: directoryManagerDN,
		VerifyPassword: func(password []byte) bool {
			return subtle.ConstantTimeCompare(password, want) == 1
		},
	}
}

// serverTLSConfig loads the directory certificate when any TLS-bearing
// feature is on (LDAPS listener or StartTLS policy) and fails closed when
// the scenario requires TLS material that was not supplied.
func serverTLSConfig(f serveFlags, c *config.Compiled) (*tls.Config, error) {
	need := f.ldapsListen != "" || c.Public.Spec.Transport.StartTLS
	if !need {
		return nil, nil
	}
	if f.tlsCertFile == "" || f.tlsKeyFile == "" {
		return nil, configFieldErr("tls.certFile", "required",
			"LDAPS or StartTLS is enabled but --tls-cert-file/--tls-key-file are not set")
	}
	cert, err := tls.LoadX509KeyPair(f.tlsCertFile, f.tlsKeyFile)
	if err != nil {
		return nil, configFieldErr("tls.certFile", "unreadable", "TLS certificate/key could not be loaded")
	}
	return &tls.Config{Certificates: []tls.Certificate{cert}}, nil
}

// enginePlugins maps the compiled plugin names onto ldapserver plugin
// hooks. Unknown names fail closed: a partially applied engine plan must
// never be served.
func enginePlugins(c *config.Compiled) ([]ldapserver.Plugin, error) {
	var out []ldapserver.Plugin
	for _, name := range c.Engine.Plugins {
		switch name {
		case "memberof":
			p, err := ldapserver.NewMemberOfPlugin(c.Engine.Suffix, c.Normalized.NestedGroups)
			if err != nil {
				return nil, fmt.Errorf("labldapd: memberof plugin: %w", err)
			}
			out = append(out, p)
		case "referint":
			p, err := ldapserver.NewRefIntPlugin(c.Engine.Suffix)
			if err != nil {
				return nil, fmt.Errorf("labldapd: referint plugin: %w", err)
			}
			out = append(out, p)
		case "account-disable":
			// nsAccountLock is enforced unconditionally in the bind path
			// (ldapserver op_bind accountLocked gate); there is no plugin
			// object to register.
		default:
			return nil, configFieldErr("spec.directory.engine", "invalid_plugin",
				"compiled engine plan names an unknown plugin: "+name)
		}
	}
	return out, nil
}

// passwordPolicy maps the compiled policy onto the ldapserver policy
// engine. Lockout parameters pass through only when lockout is enabled —
// the engine treats MaxFailures 0 as lockout-disabled, so an enabled-but-
// zero-failures scenario normalizes to the engine's disabled semantics.
func passwordPolicy(p config.NormalizedPolicy) *ldapserver.PasswordPolicy {
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
	return pp
}

// serverOptions is the engine-plan -> ldapserver.Options mapping (kept in
// one function so T-145/T-146 can review it at a glance):
//
//	Suffix              <- compiled.Engine.Suffix
//	listener addresses  <- --listen / --ldaps-listen flags (deployment, not plan)
//	TLSConfig           <- --tls-cert-file/--tls-key-file
//	AllowStartTLS       <- spec.transport.startTLS
//	AllowCleartextBind  <- spec.transport.allowCleartextBind
//	AllowAnonymousBind  <- spec.transport.allowAnonymousBind
//	PasswordPolicy      <- compiled.Engine.PasswordPolicy (see passwordPolicy)
//	Limits              <- DefaultLimits with searchSizeLimit/searchTimeLimit/
//	                       shutdownTimeout overrides from spec.limits
//	Codec/Store/Schema  <- BER codec, bbolt store, StandardSchema
//	ACITexts            <- compiled.Data.ACIs (runtime ACIs + operator ACLs)
//	NestedGroups        <- compiled.Normalized.NestedGroups (D22 groupdn walk)
//	Plugins             <- memberof, referint (account-disable is built into
//	                       the bind path); New appends the pwpolicy plugin
//	DirectoryManager    <- cn=Directory Manager + constant-time file secret
func serverOptions(c *config.Compiled, f serveFlags, tlsCfg *tls.Config, dm ldapserver.Identity, plugins []ldapserver.Plugin, st *store.Store, log *slog.Logger) (ldapserver.Options, error) {
	limits := ldapserver.DefaultLimits()
	if n := c.Public.Spec.Limits.SearchSizeLimit; n > 0 {
		limits.SearchSizeLimit = n
	}
	if d, err := time.ParseDuration(c.Public.Spec.Limits.SearchTimeLimit); err == nil && d > 0 {
		limits.SearchTimeLimit = d
	}
	if d, err := time.ParseDuration(c.Public.Spec.Limits.ShutdownTimeout); err == nil && d > 0 {
		limits.ShutdownTimeout = d
	}
	schema, err := ldapserver.StandardSchema()
	if err != nil {
		return ldapserver.Options{}, fmt.Errorf("labldapd: standard schema: %w", err)
	}
	aciTexts := make([]string, 0, len(c.Data.ACIs))
	for _, a := range c.Data.ACIs {
		aciTexts = append(aciTexts, a.Text)
	}
	transport := c.Public.Spec.Transport
	return ldapserver.Options{
		Suffix:             c.Engine.Suffix,
		LDAPAddress:        f.listen,
		LDAPSAddress:       f.ldapsListen,
		TLSConfig:          tlsCfg,
		AllowStartTLS:      transport.StartTLS,
		AllowCleartextBind: transport.AllowCleartextBind,
		AllowAnonymousBind: transport.AllowAnonymousBind,
		PasswordPolicy:     passwordPolicy(c.Engine.PasswordPolicy),
		Limits:             limits,
		Codec:              ldapserver.NewBERCodec(ldapserver.BERCodecOptions{}),
		Store:              st,
		Schema:             schema,
		ACITexts:           aciTexts,
		NestedGroups:       c.Normalized.NestedGroups,
		Plugins:            plugins,
		DirectoryManager:   dm,
		Logger:             log,
	}, nil
}

func configFieldErr(path, code, msg string) error {
	return apperr.New(apperr.CodeConfiguration, "labldapd: invalid serve configuration").
		WithField(apperr.Field{Path: path, Code: code, Message: msg})
}

// waitBound blocks until every configured listener reports its bound
// address, the server exits, or the caller gives up.
func (d *daemon) waitBound(ctx context.Context) error {
	deadline := time.Now().Add(10 * time.Second)
	for {
		if d.bound() {
			return nil
		}
		select {
		case <-d.serveDone:
			return fmt.Errorf("labldapd: listener startup failed: %w", d.exitErr)
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(5 * time.Millisecond):
		}
		if time.Now().After(deadline) {
			return errors.New("labldapd: listeners did not bind in time")
		}
	}
}

func (d *daemon) bound() bool {
	if d.wantLDAP && d.server.LDAPAddr() == nil {
		return false
	}
	if d.wantLDAPS && d.server.LDAPSAddr() == nil {
		return false
	}
	return true
}

// startHealth binds the loopback health listener. GET /health answers 200
// once the daemon is serving; the path follows the control-image
// convention (deploy/docker/labldapd-image-contract.md).
func (d *daemon) startHealth(addr string) error {
	mux := http.NewServeMux()
	mux.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			w.Header().Set("Allow", http.MethodGet)
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		_, _ = io.WriteString(w, "ok\n")
	})
	d.health = &http.Server{
		Handler:           mux,
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       10 * time.Second,
		WriteTimeout:      10 * time.Second,
		IdleTimeout:       30 * time.Second,
	}
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return fmt.Errorf("labldapd: health listener: %w", err)
	}
	d.healthLn = ln
	d.healthErr = make(chan error, 1)
	go func() { d.healthErr <- d.health.Serve(ln) }()
	return nil
}

// HealthAddr reports the bound health listener address (tests).
func (d *daemon) HealthAddr() net.Addr {
	if d.healthLn == nil {
		return nil
	}
	return d.healthLn.Addr()
}

// block runs until ctx ends (SIGTERM/SIGINT) or the LDAP server stops on
// its own, then shuts down: health listener first so orchestrators see
// unhealthiness immediately, then the ldapserver drain (bounded by
// Limits.ShutdownTimeout inside Serve), then the store close.
func (d *daemon) block(ctx context.Context, log *slog.Logger) error {
	select {
	case <-d.serveDone:
		d.stopHealth(context.Background())
		_ = d.server.Close()
		if d.exitErr == nil {
			return errors.New("labldapd: directory listeners stopped unexpectedly")
		}
		return d.exitErr
	case <-ctx.Done():
	}
	log.Info("shutdown requested")
	shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	d.stopHealth(shutdownCtx)
	d.stopServe()
	<-d.serveDone
	if err := d.server.Close(); err != nil {
		return fmt.Errorf("labldapd: store close: %w", err)
	}
	log.Info("shutdown complete")
	return d.exitErr
}

func (d *daemon) stopHealth(ctx context.Context) {
	if d.health == nil {
		return
	}
	if err := d.health.Shutdown(ctx); err != nil {
		_ = d.health.Close()
	}
	if d.healthErr != nil {
		<-d.healthErr
	}
}
