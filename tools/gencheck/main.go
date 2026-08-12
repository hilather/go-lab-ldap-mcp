package main

import (
	"fmt"
	"os"
	"strings"
)

func main() {
	if err := check(); err != nil {
		fmt.Fprintf(os.Stderr, "gencheck: %v\n", err)
		os.Exit(1)
	}
	fmt.Println("gencheck: ok")
}

func check() error {
	mod, err := os.ReadFile("go.mod")
	if err != nil {
		return err
	}
	text := string(mod)
	if !strings.Contains(text, "toolchain go1.26.5") {
		return fmt.Errorf("go.mod missing pinned toolchain go1.26.5")
	}
	if !strings.Contains(text, "go 1.26\n") {
		return fmt.Errorf("go.mod missing language version go 1.26")
	}
	pkg, err := os.ReadFile("frontend/package.json")
	if err != nil {
		return err
	}
	if !strings.Contains(string(pkg), `"packageManager": "pnpm@10.14.0"`) {
		return fmt.Errorf("frontend/package.json packageManager pin drifted")
	}
	if _, err := os.Stat("frontend/pnpm-lock.yaml"); err != nil {
		return fmt.Errorf("frontend/pnpm-lock.yaml missing: %w", err)
	}
	return nil
}
