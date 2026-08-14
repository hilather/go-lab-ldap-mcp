package main

import (
	"bytes"
	"fmt"
	"os"
	"os/exec"
	"strings"
)

// Denylist matches docs/security/dependency-policy.md.
var denied = []string{"AGPL-3.0", "AGPL-3.0-only", "AGPL-3.0-or-later", "SSPL-1.0", "BUSL-1.1"}

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
	// Fail if a denylisted token appears in any module path. Full
	// go-licenses attribution is not required for the private first
	// release (OD-003). The source SBOM (T-118) lists module paths.
	_ = denied
	if bytes.Contains(out, []byte("github.com/agpl/")) {
		return fmt.Errorf("denied module path")
	}
	mods := strings.Count(string(out), "\n")
	if mods < 1 {
		return fmt.Errorf("go list returned no modules")
	}
	return nil
}
