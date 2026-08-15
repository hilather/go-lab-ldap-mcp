package main

import (
	"fmt"
	"io"
	"strings"
)

type serveFlags struct {
	configPath     string
	dataDir        string
	listen         string
	ldapsListen    string
	tlsCertFile    string
	tlsKeyFile     string
	dmPasswordFile string
	healthListen   string
}

var errServeHelp = fmt.Errorf("help")

// parseServeFlags mirrors the hand-rolled style of cmd/labldap so the
// daemons read the same. Flag values are validated at startup in T-143.
func parseServeFlags(args []string) (serveFlags, error) {
	var f serveFlags
	next := func(i *int, name string) (string, error) {
		if *i+1 >= len(args) {
			return "", fmt.Errorf("%s requires a value", name)
		}
		*i++
		return args[*i], nil
	}
	var err error
	for i := 0; i < len(args); i++ {
		a := args[i]
		switch {
		case a == "--config":
			if f.configPath, err = next(&i, "--config"); err != nil {
				return f, err
			}
		case strings.HasPrefix(a, "--config="):
			f.configPath = strings.TrimPrefix(a, "--config=")
		case a == "--data-dir":
			if f.dataDir, err = next(&i, "--data-dir"); err != nil {
				return f, err
			}
		case strings.HasPrefix(a, "--data-dir="):
			f.dataDir = strings.TrimPrefix(a, "--data-dir=")
		case a == "--listen":
			if f.listen, err = next(&i, "--listen"); err != nil {
				return f, err
			}
		case strings.HasPrefix(a, "--listen="):
			f.listen = strings.TrimPrefix(a, "--listen=")
		case a == "--ldaps-listen":
			if f.ldapsListen, err = next(&i, "--ldaps-listen"); err != nil {
				return f, err
			}
		case strings.HasPrefix(a, "--ldaps-listen="):
			f.ldapsListen = strings.TrimPrefix(a, "--ldaps-listen=")
		case a == "--tls-cert-file":
			if f.tlsCertFile, err = next(&i, "--tls-cert-file"); err != nil {
				return f, err
			}
		case strings.HasPrefix(a, "--tls-cert-file="):
			f.tlsCertFile = strings.TrimPrefix(a, "--tls-cert-file=")
		case a == "--tls-key-file":
			if f.tlsKeyFile, err = next(&i, "--tls-key-file"); err != nil {
				return f, err
			}
		case strings.HasPrefix(a, "--tls-key-file="):
			f.tlsKeyFile = strings.TrimPrefix(a, "--tls-key-file=")
		case a == "--directory-manager-password-file":
			if f.dmPasswordFile, err = next(&i, "--directory-manager-password-file"); err != nil {
				return f, err
			}
		case strings.HasPrefix(a, "--directory-manager-password-file="):
			f.dmPasswordFile = strings.TrimPrefix(a, "--directory-manager-password-file=")
		case a == "--health-listen":
			if f.healthListen, err = next(&i, "--health-listen"); err != nil {
				return f, err
			}
		case strings.HasPrefix(a, "--health-listen="):
			f.healthListen = strings.TrimPrefix(a, "--health-listen=")
		case a == "-h", a == "--help":
			return f, errServeHelp
		default:
			return f, fmt.Errorf("unknown flag %q", a)
		}
	}
	return f, nil
}

func runServe(args []string, stdout, stderr io.Writer) int {
	if _, err := parseServeFlags(args); err != nil {
		if err == errServeHelp {
			fmt.Fprint(stdout, serveUsage)
			return 0
		}
		fmt.Fprintf(stderr, "labldapd serve: %v\n", err)
		return 2
	}
	fmt.Fprintln(stderr, "labldapd serve: server startup is not implemented (lands in T-143)")
	return 1
}
