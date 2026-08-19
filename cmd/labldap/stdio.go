package main

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"os"
	"os/signal"
	"strings"
	"syscall"

	"github.com/hilather/go-lab-ldap-mcp/internal/mcpserver"
	"github.com/hilather/go-lab-ldap-mcp/internal/observability"
)

type stdioFlags struct {
	serveFlags
	tokenFile string
}

func parseStdioFlags(args []string) (stdioFlags, error) {
	var f stdioFlags
	rest := make([]string, 0, len(args))
	for i := 0; i < len(args); i++ {
		a := args[i]
		switch {
		case a == "--token-file":
			if i+1 >= len(args) {
				return f, fmt.Errorf("--token-file requires a path")
			}
			i++
			f.tokenFile = args[i]
		case strings.HasPrefix(a, "--token-file="):
			f.tokenFile = strings.TrimPrefix(a, "--token-file=")
		case a == "--token", strings.HasPrefix(a, "--token="):
			return f, fmt.Errorf("refusing --token on the command line; use --token-file or LABLDAP_MCP_TOKEN")
		default:
			rest = append(rest, a)
		}
	}
	sf, err := parseServeFlags(rest)
	if err != nil {
		return f, err
	}
	if sf.placeholder {
		return f, fmt.Errorf("mcp-stdio does not support --placeholder")
	}
	f.serveFlags = sf
	return f, nil
}

func loadStdioToken(f stdioFlags) (string, error) {
	if strings.TrimSpace(f.tokenFile) != "" {
		b, err := os.ReadFile(f.tokenFile)
		if err != nil {
			return "", fmt.Errorf("token file unreadable")
		}
		tok := strings.TrimSpace(string(b))
		if tok == "" {
			return "", fmt.Errorf("token file is empty")
		}
		return tok, nil
	}
	tok := strings.TrimSpace(os.Getenv("LABLDAP_MCP_TOKEN"))
	if tok == "" {
		return "", fmt.Errorf("missing credentials: set LABLDAP_MCP_TOKEN or --token-file")
	}
	return tok, nil
}

func runMCPStdio(args []string, stdout, stderr io.Writer) int {
	_ = stdout // protocol uses os.Stdout; do not write logs here
	flags, err := parseStdioFlags(args)
	if err != nil {
		if err == errServeHelp {
			fmt.Fprint(stderr, stdioUsage)
			return 0
		}
		fmt.Fprintf(stderr, "labldap mcp-stdio: %v\n", err)
		fmt.Fprint(stderr, stdioUsage)
		return 2
	}
	token, err := loadStdioToken(flags)
	if err != nil {
		fmt.Fprintf(stderr, "labldap mcp-stdio: %v\n", err)
		return 2
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	log := slog.New(slog.NewTextHandler(stderr, nil))
	if observability.FormatFromEnv() == observability.FormatJSON {
		log = observability.NewLogger(stderr, observability.FormatJSON, observability.CurrentBuild("labldap"))
	}

	built, err := compileControl(ctx, flags.serveFlags)
	if err != nil {
		printConfigError(stderr, err)
		return 1
	}
	opt, svc, closer, err := serverOptionsFromCompiled(built, flags.serveFlags, log)
	if err != nil {
		fmt.Fprintf(stderr, "labldap mcp-stdio: %v\n", err)
		return 1
	}
	if closer != nil {
		defer closer()
	}
	if svc == nil || opt.Registry == nil {
		fmt.Fprintln(stderr, "labldap mcp-stdio: directory not attached")
		return 1
	}
	p, ok := opt.Registry.Lookup(token)
	if !ok {
		fmt.Fprintln(stderr, "labldap mcp-stdio: invalid credentials")
		return 2
	}

	mcpCfg := built.Public.Spec.Management.MCP
	s, err := mcpserver.New(mcpserver.Options{
		Registry: opt.Registry,
		Services: svc,
		Logger:   log,
		MaxBody:  built.Public.Spec.Limits.MaxRequestBodyBytes,
		Flags: mcpserver.RegisterFlags{
			Mutations: mcpCfg.RegisterMutations,
			Password:  mcpCfg.RegisterPassword,
			Reset:     mcpCfg.RegisterReset,
			Export:    mcpCfg.RegisterExport,
		},
	})
	if err != nil {
		fmt.Fprintf(stderr, "labldap mcp-stdio: %v\n", err)
		return 1
	}
	s.SetActor(p)
	if err := s.RunStdio(ctx); err != nil && ctx.Err() == nil {
		fmt.Fprintf(stderr, "labldap mcp-stdio: %v\n", err)
		return 1
	}
	return 0
}

const stdioUsage = `Usage:
  labldap mcp-stdio --config FILE [--token-file FILE] [--ldap-url URL]
                    [--directory-ca-file FILE] [--directory-host NAME]

mcp-stdio speaks the official MCP protocol on stdin/stdout. Structured
logs go only to stderr. Do not write anything else to stdout.

The process actor is the compiled token from LABLDAP_MCP_TOKEN or
--token-file (never --token). Missing or invalid credentials exit
without starting the protocol. Tool scopes match Streamable HTTP /mcp.

Directory flags match serve: --ldap-url, --directory-ca-file,
--directory-host (or LABLDAP_LDAP_URL, LABLDAP_DIRECTORY_CA_FILE,
LABLDAP_DIRECTORY_HOST).
`
