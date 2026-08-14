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
	"github.com/hilather/go-lab-ldap-mcp/internal/auth"
	"github.com/hilather/go-lab-ldap-mcp/internal/config"
	"github.com/hilather/go-lab-ldap-mcp/internal/directory/ds389"
	"github.com/hilather/go-lab-ldap-mcp/internal/mcpserver"
	"github.com/hilather/go-lab-ldap-mcp/internal/observability"
)

const defaultListen = "127.0.0.1:8443"

func runServe(args []string, stdout, stderr io.Writer) int {
	_ = stdout
	placeholder := false
	configPath := ""
	for i := 0; i < len(args); i++ {
		switch args[i] {
		case "--placeholder":
			placeholder = true
		case "--config":
			if i+1 >= len(args) {
				fmt.Fprintln(stderr, "labldap serve: --config requires a path")
				return 2
			}
			i++
			configPath = args[i]
		case "-h", "--help":
			fmt.Fprint(stdout, serveUsage)
			return 0
		default:
			fmt.Fprintf(stderr, "labldap serve: unknown flag %q\n", args[i])
			return 2
		}
	}
	if !placeholder && configPath == "" {
		fmt.Fprintln(stderr, "labldap serve: --config PATH or --placeholder is required")
		fmt.Fprint(stderr, serveUsage)
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
	if placeholder {
		listen = os.Getenv("LABLDAP_LISTEN")
		if listen == "" {
			listen = defaultListen
		}
		srv, err := api.New(api.Options{
			Ready:          func() bool { return false },
			Logger:         log,
			MetricsEnabled: true,
		})
		if err != nil {
			fmt.Fprintf(stderr, "labldap serve: %v\n", err)
			return 1
		}
		handler = mountTransports(srv.Handler(), mcpserver.Disabled())
		readTO, writeTO, idleTO, stopTO = srv.Timeouts(30*time.Second, 15*time.Second)
	} else {
		built, err := compileControl(ctx, configPath)
		if err != nil {
			printConfigError(stderr, err)
			return 1
		}
		// Composition root (KD-R15): map compiled geometry onto the 389 DS
		// runtime config. The live pool is attached when T-073 readiness lands.
		_ = runtimeConfigFromCompiled(built)
		opt, err := serverOptionsFromCompiled(built, log)
		if err != nil {
			fmt.Fprintf(stderr, "labldap serve: %v\n", err)
			return 1
		}
		srv, err := api.New(opt)
		if err != nil {
			fmt.Fprintf(stderr, "labldap serve: %v\n", err)
			return 1
		}
		mcpH, err := mcpHandlerFromCompiled(built, opt.Registry, log)
		if err != nil {
			fmt.Fprintf(stderr, "labldap serve: %v\n", err)
			return 1
		}
		handler = mountTransports(srv.Handler(), mcpH)
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

func serverOptionsFromCompiled(c *config.Compiled, log *slog.Logger) (api.Options, error) {
	tokens := make([]auth.Token, 0, len(c.Normalized.Tokens))
	for _, t := range c.Normalized.Tokens {
		tokens = append(tokens, auth.Token{ID: t.ID, Scopes: t.Scopes, Secret: t.Secret.Value})
	}
	reg, err := auth.NewRegistry(tokens)
	if err != nil {
		return api.Options{}, err
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
	return api.Options{
		Registry:       reg,
		Sessions:       auth.NewStore(sessCfg),
		Ready:          func() bool { return false },
		Logger:         log,
		AllowedOrigins: append([]string(nil), c.Public.Spec.Management.CORS.AllowedOrigins...),
		MaxBody:        c.Public.Spec.Limits.MaxRequestBodyBytes,
		ForceSecure:    false, // cookie Secure follows r.TLS until serve terminates TLS (OD-014)
		MetricsAuth:    c.Public.Spec.Management.Metrics.RequireAuth,
		MetricsEnabled: c.Public.Spec.Management.Metrics.Enabled == nil || *c.Public.Spec.Management.Metrics.Enabled,
	}, nil
}

func mountTransports(rest, mcp http.Handler) http.Handler {
	mux := http.NewServeMux()
	if mcp == nil {
		mcp = mcpserver.Disabled()
	}
	mux.Handle(mcpserver.MountPath, mcp)
	mux.Handle("/", rest)
	return mux
}

func mcpHandlerFromCompiled(c *config.Compiled, reg *auth.Registry, log *slog.Logger) (http.Handler, error) {
	if c == nil || c.Public == nil || (c.Public.Spec.Management.MCP.Enabled != nil && !*c.Public.Spec.Management.MCP.Enabled) {
		return mcpserver.Disabled(), nil
	}
	mcpCfg := c.Public.Spec.Management.MCP
	s, err := mcpserver.New(mcpserver.Options{
		Registry: reg,
		// Application services attach when the runtime pool lands (T-073).
		// Nil keeps tool handlers returning directory unavailable, not panic.
		Services:       nil,
		Logger:         log,
		AllowedOrigins: append([]string(nil), c.Public.Spec.Management.CORS.AllowedOrigins...),
		MaxBody:        c.Public.Spec.Limits.MaxRequestBodyBytes,
		Flags: mcpserver.RegisterFlags{
			Mutations: mcpCfg.RegisterMutations,
			Password:  mcpCfg.RegisterPassword,
			Reset:     mcpCfg.RegisterReset,
			Export:    mcpCfg.RegisterExport,
		},
	})
	if err != nil {
		return nil, err
	}
	return s.Handler(), nil
}

func runtimeConfigFromCompiled(c *config.Compiled) ds389.RuntimeConfig {
	n := c.Normalized
	return ds389.RuntimeConfig{
		Suffix:          n.Suffix.String(),
		PeopleDN:        n.PeopleDN.String(),
		GroupsDN:        n.GroupsDN.String(),
		RuntimeDN:       n.Runtime.DN,
		MarkerDN:        c.Data.Marker,
		NestedGroups:    n.NestedGroups,
		PageSizeDefault: c.Public.Spec.Limits.PageSizeDefault,
		PageSizeMax:     c.Public.Spec.Limits.PageSizeMax,
		SearchSizeLimit: c.Public.Spec.Limits.SearchSizeLimit,
		MaxFilterDepth:  c.Public.Spec.Limits.MaxFilterDepth,
		MaxFilterLength: c.Public.Spec.Limits.MaxFilterLength,
	}
}

const serveUsage = `Usage:
  labldap serve --config FILE
  labldap serve --placeholder

serve starts the management HTTP listener (REST, MCP, and later UI).
--placeholder listens on LABLDAP_LISTEN (default 127.0.0.1:8443) without
loading a scenario or contacting LDAP. GET /health is live; GET /health/ready
is 503 until the directory is ready. POST /mcp is 501 until a scenario enables MCP.
`
