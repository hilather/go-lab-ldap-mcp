package main

import (
	"fmt"
	"io"
	"os"

	"github.com/hilather/go-lab-ldap-mcp/internal/observability"
)

const usage = `labldap — LabLDAP control plane

Serves the laboratory management plane: REST, MCP, and the administrative UI.
This binary does not implement the LDAP wire protocol. Directory data lives in
389 Directory Server. This process binds as a restricted service account and
never receives Directory Manager credentials or a Docker socket.

Usage:
  labldap [command]

Commands:
  help       Show this help (also -h, --help)
  version    Print component and version fields
  validate   Compile a scenario YAML (exit 0 if valid)
  normalize  Print redacted normalized JSON
  plan       Print a redacted engine/data plan (JSON)
  serve      Start the management HTTP listener

Structured logs go to stderr. Set LABLDAP_LOG_FORMAT=json for JSON logs.

See AGENTS.md and docs/design/labldap-implementation-design.md.
`

func main() {
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr))
}

func run(args []string, stdout, stderr io.Writer) int {
	info, _ := observability.StartupLogger(stderr, "labldap")
	if len(args) == 0 || isHelp(args[0]) {
		fmt.Fprint(stdout, usage)
		return 0
	}
	if isVersion(args[0]) {
		observability.WriteVersion(stdout, info)
		return 0
	}
	switch args[0] {
	case "validate", "normalize", "plan":
		return runConfigCommand(args[0], args[1:], stdout, stderr)
	case "serve":
		return runServe(args[1:], stdout, stderr)
	}
	fmt.Fprintf(stderr, "labldap: unknown command %q\n\n", args[0])
	fmt.Fprint(stderr, usage)
	return 2
}

func isHelp(arg string) bool {
	switch arg {
	case "help", "-h", "-help", "--help":
		return true
	default:
		return false
	}
}

func isVersion(arg string) bool {
	switch arg {
	case "version", "-version", "--version":
		return true
	default:
		return false
	}
}
