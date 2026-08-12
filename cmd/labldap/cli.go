package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/hilather/go-lab-ldap-mcp/internal/apperr"
	"github.com/hilather/go-lab-ldap-mcp/internal/config"
)

func runConfigCommand(cmd string, args []string, stdout, stderr io.Writer) int {
	path, rest := "", args
	if len(args) > 0 && !strings.HasPrefix(args[0], "-") {
		path = args[0]
		rest = args[1:]
	}
	jsonOut := false
	for _, a := range rest {
		switch a {
		case "--json":
			jsonOut = true
		case "--redact":
			// default; accepted for compatibility
		case "--reveal", "--show-secrets":
			fmt.Fprintln(stderr, "labldap: refusing to print secrets")
			return 2
		default:
			fmt.Fprintf(stderr, "labldap: unknown flag %q\n", a)
			return 2
		}
	}
	if path == "" {
		fmt.Fprintln(stderr, "labldap: configuration file path is required")
		return 2
	}
	src, err := os.ReadFile(path)
	if err != nil {
		fmt.Fprintf(stderr, "labldap: %v\n", err)
		return 2
	}
	compiled, err := config.Compile(context.Background(), src, path, config.LoadOptions{
		Caller:  config.CallerCLI,
		Secrets: config.DirSecretResolver(filepath.Dir(path)),
	})
	if err != nil {
		printConfigError(stderr, err)
		return 1
	}
	switch cmd {
	case "validate":
		fmt.Fprintln(stdout, "ok")
		return 0
	case "normalize":
		b, err := compiled.NormalizeJSON()
		if err != nil {
			fmt.Fprintf(stderr, "labldap: %v\n", err)
			return 1
		}
		stdout.Write(b)
		return 0
	case "plan":
		if jsonOut || true { // plan is always JSON; redact is default
			b, err := compiled.RedactedJSON()
			if err != nil {
				fmt.Fprintf(stderr, "labldap: %v\n", err)
				return 1
			}
			stdout.Write(b)
		}
		return 0
	default:
		return 2
	}
}

func printConfigError(w io.Writer, err error) {
	var e *apperr.Error
	if errors.As(err, &e) {
		fmt.Fprintf(w, "labldap: %s\n", e.PublicMessage())
		for _, f := range e.Fields() {
			fmt.Fprintf(w, "  %s: %s (%s)\n", f.Path, f.Message, f.Code)
		}
		return
	}
	fmt.Fprintf(w, "labldap: %v\n", err)
}
