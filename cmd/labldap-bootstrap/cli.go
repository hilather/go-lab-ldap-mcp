package main

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"os"
	"os/signal"
	"path/filepath"

	"github.com/hilather/go-lab-ldap-mcp/internal/bootstrap"
	"github.com/hilather/go-lab-ldap-mcp/internal/config"
	"github.com/hilather/go-lab-ldap-mcp/internal/directory/ds389"
)

func runBootstrap(cmd string, args []string, stdout, stderr io.Writer, logger *slog.Logger) int {
	opt, err := bootstrap.ParseArgs(cmd, args)
	if err != nil {
		fmt.Fprintf(stderr, "labldap-bootstrap: %s\n", err.Error())
		return 2
	}
	opt.Log = logger
	opt.Waiter = ds389.Admin{}
	eng := ds389.Engine{}
	opt.Backend = eng
	opt.TLS = eng
	opt.Policy = eng
	opt.Plugins = eng
	opt.Tree = eng
	opt.ACIs = eng
	opt.Seed = eng
	opt.VerifyRuntime = eng
	opt.VerifyApp = eng
	opt.Drift = eng
	opt.Marker = eng
	opt.Capabilities = eng

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()

	// T-123: fail closed when the scenario selects an engine this build does
	// not wire (only 389ds until T-146). The check runs after a successful
	// compile and before any wait/dial. plan performs no network I/O, so it
	// still prints the compiled plan and then exits non-zero.
	gateErr := engineAvailabilityGate(ctx, opt.ConfigPath)
	if gateErr != nil && cmd != "plan" {
		sum := bootstrap.Summary{Command: cmd, Source: opt.ConfigPath, Phases: []bootstrap.PhaseResult{}}
		bootstrap.WriteSummary(stdout, stderr, sum, gateErr)
		return bootstrap.ExitCode(gateErr)
	}

	sum, err := bootstrap.Run(ctx, opt, stdout, stderr)
	if err == nil {
		err = gateErr
	}
	bootstrap.WriteSummary(stdout, stderr, sum, err)
	return bootstrap.ExitCode(err)
}

// engineAvailabilityGate compiles the scenario and reports the stable
// engine_not_available error when it selects an unwired engine. A read or
// compile failure returns nil so bootstrap.Run stays the single reporter of
// configuration errors.
func engineAvailabilityGate(ctx context.Context, configPath string) error {
	src, err := os.ReadFile(configPath)
	if err != nil {
		return nil
	}
	compiled, err := config.Compile(ctx, src, configPath, config.LoadOptions{
		Caller:  config.CallerBootstrap,
		Secrets: config.DirSecretResolver(filepath.Dir(configPath)),
	})
	if err != nil {
		return nil
	}
	return config.RequireAvailableEngine(compiled.Engine.Engine)
}
