package main

import (
	"fmt"
	"io"
	"os"
)

const usage = `labldap — LabLDAP control plane

Serves the laboratory management plane: REST, MCP, and the administrative UI.
This binary does not implement the LDAP wire protocol. Directory data lives in
389 Directory Server. This process binds as a restricted service account and
never receives Directory Manager credentials or a Docker socket.

Usage:
  labldap [command]

Commands:
  help    Show this help (also -h, --help)

This is the T-001 scaffold. Serve, configuration, and version commands land in
later tasks (see TASKS.md).

See AGENTS.md and docs/design/labldap-implementation-design.md.
`

func main() {
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr))
}

func run(args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 || isHelp(args[0]) {
		fmt.Fprint(stdout, usage)
		return 0
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
