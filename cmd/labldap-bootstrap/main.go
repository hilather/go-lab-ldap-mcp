package main

import (
	"fmt"
	"io"
	"os"

	"github.com/hilather/go-lab-ldap-mcp/internal/observability"
)

const usage = `labldap-bootstrap — LabLDAP one-shot directory bootstrap

Validates configuration, waits for 389 Directory Server, and (in later
tasks) creates the backend, applies engine settings, seeds the managed
suffix, creates the restricted runtime account, verifies allow/deny, and
writes the baseline marker.

This command is the only LabLDAP process that may receive Directory Manager
credentials, and only through a secret file — never a command-line value.
It does not implement the LDAP wire protocol and must not mount a Docker socket.

Usage:
  labldap-bootstrap [command]

Commands:
  help       Show this help (also -h, --help)
  version    Print component and version fields
  apply      Load config, wait for the engine, bind as Directory Manager
  validate   Same wait/bind path as apply; later inspect/drift stay read-only
  plan       Compile and print a redacted plan JSON summary (offline)

Flags (apply / validate):
  --config PATH
  --directory-manager-password-file PATH
  --ldap-url URL                 optional ldaps://host:port override
  --directory-ca-file PATH       PEM CA used to verify LDAPS
  --directory-host HOST          TLS server name (default 127.0.0.1)
  --deadline DURATION            default 90s

--directory-host is the certificate name, not the dial address. When the
instance cert SAN is the container hostname, pass that here and put the
published address in --ldap-url.

plan accepts --config and optional --directory-manager-password-file.

This apply currently runs phases load and wait. Remaining phases
(backend through marker) land in T-029+.

Structured logs go to stderr. Set LABLDAP_LOG_FORMAT=json for JSON logs.

See AGENTS.md and docs/design/labldap-implementation-design.md.
`

func main() {
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr))
}

func run(args []string, stdout, stderr io.Writer) int {
	info, logger := observability.StartupLogger(stderr, "labldap-bootstrap")
	if len(args) == 0 || isHelp(args[0]) {
		fmt.Fprint(stdout, usage)
		return 0
	}
	if isVersion(args[0]) {
		observability.WriteVersion(stdout, info)
		return 0
	}
	switch args[0] {
	case "apply", "validate", "plan":
		return runBootstrap(args[0], args[1:], stdout, stderr, logger)
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

func isVersion(arg string) bool {
	switch arg {
	case "version", "-version", "--version":
		return true
	default:
		return false
	}
}
