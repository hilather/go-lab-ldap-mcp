package main

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"os"
	"os/signal"

	"github.com/hilather/go-lab-ldap-mcp/internal/bootstrap"
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

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()

	sum, err := bootstrap.Run(ctx, opt, stdout, stderr)
	bootstrap.WriteSummary(stdout, stderr, sum, err)
	return bootstrap.ExitCode(err)
}
