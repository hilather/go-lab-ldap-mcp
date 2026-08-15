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

Native mode is lab-scoped and is not ready until milestone M9 completes.

Usage:
  labldapd [command]

Commands:
  help       Show this help (also -h, --help)
  version    Print component and version fields
  serve      Start the directory listeners (lands in T-143)

Structured logs go to stderr. Set LABLDAP_LOG_FORMAT=json for JSON logs.

See AGENTS.md, docs/adr/0009-native-engine-topology-and-storage.md, and
docs/design/native-engine-parity-contract.md.
`

const serveUsage = `Usage:
  labldapd serve [--config FILE] [flags]

serve starts the native directory engine: it applies the compiled engine
plan at start (suffix, TLS materials, password policy, plugin hooks), opens
the bbolt store in the data directory, and binds the directory listeners.

Flags:
  --config PATH                            scenario YAML (engine plan source)
  --data-dir PATH                          bbolt data directory (default /data)
  --listen ADDR                            LDAP listener (default 127.0.0.1:3389)
  --ldaps-listen ADDR                      LDAPS listener (default 127.0.0.1:3636)
  --tls-cert-file PATH                     TLS certificate PEM
  --tls-key-file PATH                      TLS private key PEM
  --directory-manager-password-file PATH   Directory Manager secret file
  --health-listen ADDR                     health listener (loopback default)

Listener hosts default to loopback when unspecified. Server startup itself
is not implemented yet; it lands in T-143.
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
