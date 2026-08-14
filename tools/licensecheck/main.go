package main

import (
	"fmt"
	"os"
	"os/exec"
	"strings"
)

// Denylist matches docs/security/dependency-policy.md. We scan module
// paths (and versions) for these tokens because go-licenses is not pinned.
var denied = []string{"agpl-3.0", "agpl", "sspl-1.0", "sspl", "busl-1.1", "busl"}

func main() {
	if err := run(); err != nil {
		fmt.Fprintf(os.Stderr, "licensecheck: %v\n", err)
		os.Exit(1)
	}
	fmt.Println("licensecheck: ok")
}

func run() error {
	cmd := exec.Command("go", "list", "-m", "-f", "{{.Path}} {{.Version}}", "all")
	cmd.Env = append(os.Environ(), "GOTOOLCHAIN=go1.26.5")
	out, err := cmd.Output()
	if err != nil {
		return fmt.Errorf("go list: %w", err)
	}
	lines := strings.Split(string(out), "\n")
	if len(lines) < 1 || strings.TrimSpace(string(out)) == "" {
		return fmt.Errorf("go list returned no modules")
	}
	for _, line := range lines {
		if tok := deniedToken(line); tok != "" {
			return fmt.Errorf("denied license token %q in module %s", tok, strings.TrimSpace(line))
		}
	}
	return nil
}

func deniedToken(line string) string {
	low := strings.ToLower(line)
	if low == "" {
		return ""
	}
	for _, tok := range denied {
		if strings.Contains(low, tok) {
			return tok
		}
	}
	return ""
}
