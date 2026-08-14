package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	"github.com/hilather/go-lab-ldap-mcp/internal/api"
	"github.com/hilather/go-lab-ldap-mcp/internal/app"
	"github.com/hilather/go-lab-ldap-mcp/internal/auth"
	"github.com/hilather/go-lab-ldap-mcp/internal/config"
	"github.com/hilather/go-lab-ldap-mcp/internal/directory/ds389"
	"github.com/hilather/go-lab-ldap-mcp/internal/observability"
)

const defaultListen = "127.0.0.1:8443"

func runServe(args []string, stdout, stderr io.Writer) int {
	_ = stdout
	flags, err := parseServeFlags(args)
	if err != nil {
		if errors.Is(err, errServeHelp) {
			fmt.Fprint(stdout, serveUsage)
			return 0
		}
		fmt.Fprintf(stderr, "labldap serve: %v\n", err)
		if flags.configPath == "" && !flags.placeholder {
			fmt.Fprint(stderr, serveUsage)
		}
		return 2
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	log := slog.New(slog.NewTextHandler(stderr, nil))
	if observability.FormatFromEnv() == observability.FormatJSON {
		info := observability.CurrentBuild("labldap")
		log = observability.NewLogger(stderr, observability.FormatJSON, info)
	}

	var (
		handler http.Handler
		listen  string
		readTO  time.Duration
		writeTO time.Duration
		idleTO  time.Duration
		stopTO  time.Duration
	)
	if flags.placeholder {
		listen = os.Getenv("LABLDAP_LISTEN")
		if listen == "" {
			listen = defaultListen
		}
		srv, err := api.New(api.Options{
			Ready:          func() bool { return false },
			Logger:         log,
			MetricsEnabled: true,
			Metrics:        observability.NewRegistry(observability.CurrentBuild("labldap")),
			Build:          observability.CurrentBuild("labldap"),
			CursorKey:      config.NewCursorKey(),
		})
		if err != nil {
			fmt.Fprintf(stderr, "labldap serve: %v\n", err)
			return 1
		}
		handler = srv.Handler()
		readTO, writeTO, idleTO, stopTO = srv.Timeouts(30*time.Second, 15*time.Second)
	} else {
		built, err := compileControl(ctx, flags.configPath)
		if err != nil {
			printConfigError(stderr, err)
			return 1
		}
		opt, closer, err := serverOptionsFromCompiled(built, flags, log)
		if err != nil {
			fmt.Fprintf(stderr, "labldap serve: %v\n", err)
			return 1
		}
		if closer != nil {
			defer closer()
		}
		srv, err := api.New(opt)
		if err != nil {
			fmt.Fprintf(stderr, "labldap serve: %v\n", err)
			return 1
		}
		handler = srv.Handler()
		listen = built.Public.Spec.Management.Listen
		reqTO, err := time.ParseDuration(built.Public.Spec.Limits.RequestTimeout)
		if err != nil {
			reqTO = 30 * time.Second
		}
		shutTO, err := time.ParseDuration(built.Public.Spec.Limits.ShutdownTimeout)
		if err != nil {
			shutTO = 15 * time.Second
		}
		readTO, writeTO, idleTO, stopTO = srv.Timeouts(reqTO, shutTO)
	}

	httpSrv := &http.Server{
		Addr:              listen,
		Handler:           handler,
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       readTO,
		WriteTimeout:      writeTO,
		IdleTimeout:       idleTO,
	}
	errCh := make(chan error, 1)
	go func() {
		errCh <- httpSrv.ListenAndServe()
	}()
	select {
	case <-ctx.Done():
		shutCtx, cancel := context.WithTimeout(context.Background(), stopTO)
		defer cancel()
		if err := httpSrv.Shutdown(shutCtx); err != nil {
			fmt.Fprintf(stderr, "labldap serve: shutdown: %v\n", err)
			return 1
		}
		return 0
	case err := <-errCh:
		if err != nil && !errors.Is(err, http.ErrServerClosed) {
			fmt.Fprintf(stderr, "labldap serve: %v\n", err)
			return 1
		}
		return 0
	}
}

func compileControl(ctx context.Context, path string) (*config.Compiled, error) {
	src, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return config.Compile(ctx, src, path, config.LoadOptions{
		Caller:  config.CallerControl,
		Secrets: config.DirSecretResolver(filepath.Dir(path)),
	})
}

func serverOptionsFromCompiled(c *config.Compiled, flags serveFlags, log *slog.Logger) (api.Options, func(), error) {
	tokens := make([]auth.Token, 0, len(c.Normalized.Tokens))
	for _, t := range c.Normalized.Tokens {
		tokens = append(tokens, auth.Token{ID: t.ID, Scopes: t.Scopes, Secret: t.Secret.Value})
	}
	reg, err := auth.NewRegistry(tokens)
	if err != nil {
		return api.Options{}, nil, err
	}
	sessCfg := auth.DefaultSessionConfig()
	if d, err := time.ParseDuration(c.Public.Spec.Management.Session.IdleTimeout); err == nil && d > 0 {
		sessCfg.Idle = d
	}
	if d, err := time.ParseDuration(c.Public.Spec.Management.Session.AbsoluteTimeout); err == nil && d > 0 {
		sessCfg.Absolute = d
	}
	if c.Public.Spec.Management.Session.MaxSessions > 0 {
		sessCfg.Max = c.Public.Spec.Management.Session.MaxSessions
	}
	build := observability.CurrentBuild("labldap")
	metrics := observability.NewRegistry(build)
	rl := c.Public.Spec.Limits.RateLimit
	win := app.NewWindow(rl.PasswordPerMinute, rl.BindTestPerMinute, rl.RequestsPerMinute, rl.ResetPerHour)
	b := &apiOptionsBuilder{compiled: c, flags: flags, log: log, metrics: metrics, limit: win}
	// Composition root (KD-R15): attach the live pool and app services.
	// Construction failure leaves handlers unwired and readiness false;
	// liveness still serves.
	if err := attachDirectory(b); err != nil {
		log.Error("directory not attached", slog.String("err", err.Error()))
	}
	ready := func() bool { return false }
	diag := func() app.Diagnostics { return app.Diagnostics{Reset: app.ResetHint{State: "Ready"}} }
	if b.probe != nil {
		ready = func() bool {
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			return b.probe.Ready(ctx)
		}
		diag = func() app.Diagnostics {
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			return b.probe.Evaluate(ctx)
		}
	}
	if b.pool != nil {
		pool := b.pool
		gate := b.gate
		metrics.SetSnapshots(func() (int, int, int, int) {
			st := pool.Stats()
			return st.Active, st.Idle, st.Max, st.Waiters
		}, func() bool {
			return gate != nil && gate.InProgress()
		})
	}
	opt := api.Options{
		Registry:        reg,
		Sessions:        auth.NewStore(sessCfg),
		Ready:           ready,
		Logger:          log,
		AllowedOrigins:  append([]string(nil), c.Public.Spec.Management.CORS.AllowedOrigins...),
		MaxBody:         c.Public.Spec.Limits.MaxRequestBodyBytes,
		ForceSecure:     false, // cookie Secure follows r.TLS until serve terminates TLS (OD-014)
		MetricsAuth:     c.Public.Spec.Management.Metrics.RequireAuth,
		MetricsEnabled:  c.Public.Spec.Management.Metrics.Enabled == nil || *c.Public.Spec.Management.Metrics.Enabled,
		Metrics:         metrics,
		Limiter:         api.FuncLimiter(win.AllowKey),
		System:          b.system,
		Users:           b.users,
		Groups:          b.groups,
		Query:           b.query,
		Reset:           b.reset,
		Export:          b.export,
		Audit:           b.audit,
		AuditHook:       b.auditHook,
		Diagnostics:     diag,
		Build:           build,
		PageSizeDefault: c.Public.Spec.Limits.PageSizeDefault,
		PageSizeMax:     c.Public.Spec.Limits.PageSizeMax,
		CursorKey:       config.NewCursorKey(),
	}
	closer := func() {
		if b.pool != nil {
			_ = b.pool.Close()
		}
	}
	return opt, closer, nil
}

func runtimeConfigFromCompiled(c *config.Compiled) ds389.RuntimeConfig {
	n := c.Normalized
	return ds389.RuntimeConfig{
		Suffix:           n.Suffix.String(),
		PeopleDN:         n.PeopleDN.String(),
		GroupsDN:         n.GroupsDN.String(),
		RuntimeDN:        n.Runtime.DN,
		MarkerDN:         c.Data.Marker,
		NestedGroups:     n.NestedGroups,
		PageSizeDefault:  c.Public.Spec.Limits.PageSizeDefault,
		PageSizeMax:      c.Public.Spec.Limits.PageSizeMax,
		SearchSizeLimit:  c.Public.Spec.Limits.SearchSizeLimit,
		MaxFilterDepth:   c.Public.Spec.Limits.MaxFilterDepth,
		MaxFilterLength:  c.Public.Spec.Limits.MaxFilterLength,
		ExportMaxEntries: c.Public.Spec.Limits.ExportMaxEntries,
		ExportMaxBytes:   c.Public.Spec.Limits.ExportMaxBytes,
	}
}

const serveUsage = `Usage:
  labldap serve --config FILE [--ldap-url URL] [--directory-ca-file FILE] [--directory-host NAME]
  labldap serve --placeholder

serve starts the management HTTP listener (REST, later MCP and UI).
GET /health is process liveness and never consults LDAP.
GET /health/ready requires runtime bind, marker, Directory revision match,
required capabilities, and no reset.

--ldap-url defaults to ldaps://127.0.0.1:<compiled ldaps port> (or LABLDAP_LDAP_URL).
--directory-ca-file is required unless insecure lab mode is set
(LABLDAP_DIRECTORY_CA_FILE). --directory-host is the TLS server name
(LABLDAP_DIRECTORY_HOST).

GET /metrics is Prometheus text. Default requireAuth is false: restrict
the listener with loopback or network policy, or set
spec.management.metrics.requireAuth.

--placeholder listens on LABLDAP_LISTEN (default 127.0.0.1:8443) without
loading a scenario or contacting LDAP.
`
