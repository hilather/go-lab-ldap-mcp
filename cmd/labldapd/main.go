package main

import (
	"fmt"
	"io"
	"os"

	"github.com/hilather/go-lab-ldap-mcp/internal/observability"
)

const usage = `labldapd — LabLDAP native directory engine

Serves the laboratory directory itself: LDAPv3 over LDAP, LDAPS, and
StartTLS with bbolt persistence (ADR-0008, ADR-0009). This binary is the
engine, not the control plane: labldap and labldap-bootstrap stay LDAP
clients of it, and Directory Manager credentials reach it only through a
secret file — never a command-line value.

Native mode is lab-scoped and ready as opt-in engine: native. Omitting the
field still defaults to 389ds.

Usage:
  labldapd [command]

Commands:
  help       Show this help (also -h, --help)
  version    Print component and version fields
  serve      Start the directory listeners (T-143)

Structured logs go to stderr. Set LABLDAP_LOG_FORMAT=json for JSON logs.

See AGENTS.md, docs/adr/0009-native-engine-topology-and-storage.md, and
docs/design/native-engine-parity-contract.md.
`

const serveUsage = `Usage:
  labldapd serve --config FILE --directory-manager-password-file PATH [flags]

serve starts the native directory engine: it compiles the scenario, applies
the engine plan at start (suffix, TLS materials, password policy, plugin
hooks, runtime ACIs), publishes the applied plan at cn=config for bootstrap
read-back, opens the bbolt store in the data directory, and binds the
directory listeners. SIGTERM/SIGINT shut down gracefully.

Flags:
  --config PATH                            scenario YAML (engine plan source; required)
  --data-dir PATH                          bbolt data directory (default /data)
  --listen ADDR                            LDAP listener (default 127.0.0.1:3389; empty disables)
  --ldaps-listen ADDR                      LDAPS listener (default 127.0.0.1:3636; empty disables)
  --tls-cert-file PATH                     TLS certificate PEM (required with LDAPS/StartTLS)
  --tls-key-file PATH                      TLS private key PEM (required with LDAPS/StartTLS)
  --directory-manager-password-file PATH   Directory Manager secret file (required)
  --health-listen ADDR                     health listener (default 127.0.0.1:8389; empty disables)

Listener hosts default to loopback when unspecified. The scenario must
select engine: native; the daemon never reads user/runtime/token secret
files (the data plane belongs to labldap-bootstrap). GET /health on the
health listener answers 200 once the directory listeners are bound.

Exit codes: 0 clean shutdown, 1 startup/runtime failure, 2 flag error.
`

func main() {
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr))
}

func run(args []string, stdout, stderr io.Writer) int {
	info, _ := observability.StartupLogger(stderr, "labldapd")
	if len(args) == 0 || isHelp(args[0]) {
		fmt.Fprint(stdout, usage)
		return 0
	}
	if isVersion(args[0]) {
		observability.WriteVersion(stdout, info)
		return 0
	}
	switch args[0] {
	case "serve":
		return runServe(args[1:], stdout, stderr)
	}
	fmt.Fprintf(stderr, "labldapd: unknown command %q\n\n", args[0])
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
