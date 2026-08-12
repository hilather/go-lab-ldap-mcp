package main

import (
	"fmt"
	"io"
	"os"
)

const usage = `labldap-bootstrap — LabLDAP one-shot directory bootstrap

Validates configuration, creates or verifies the 389 Directory Server backend,
applies engine settings, seeds the managed suffix, creates the restricted
runtime service account, verifies allow/deny, and writes the baseline marker.

This command is the only LabLDAP process that may receive Directory Manager
credentials, and only through a secret file — never a command-line value.
It does not implement the LDAP wire protocol and must not mount a Docker socket.

Usage:
  labldap-bootstrap [command]

Commands:
  help    Show this help (also -h, --help)

This is the T-001 scaffold. apply, validate, and plan commands land in later
tasks (see TASKS.md, starting at T-027).

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
	fmt.Fprintf(stderr, "labldap-bootstrap: unknown command %q\n\n", args[0])
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
