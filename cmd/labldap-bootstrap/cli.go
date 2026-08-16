package main

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"os"
	"os/signal"

	"github.com/hilather/go-lab-ldap-mcp/internal/bootstrap"
)

func runBootstrap(cmd string, args []string, stdout, stderr io.Writer, logger *slog.Logger) int {
	opt, err := bootstrap.ParseArgs(cmd, args)
	if err != nil {
		fmt.Fprintf(stderr, "labldap-bootstrap: %s\n", err.Error())
		return 2
	}
	opt.Log = logger

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()

	// T-146: select the reconciler set for the scenario's engine (389ds or
	// native; see engine.go). The gate fails closed on an unwired engine:
	// the check runs after a successful compile and before any wait/dial.
	// plan performs no network I/O, so it still prints the compiled plan
	// and then exits non-zero if the gate ever rejects an engine.
	gateErr := wireEngineReconcilers(ctx, &opt)
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
