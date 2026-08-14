// labldap-compose-preflight checks OD-020 minimum Docker / Compose versions.
package main

import (
	"fmt"
	"os"
	"os/exec"
	"strconv"
	"strings"
)

const (
	minEngineMajor  = 24
	minComposeMajor = 2
	minComposeMinor = 24
)

func main() {
	os.Exit(run(os.Stdout, os.Stderr))
}

func run(stdout, stderr *os.File) int {
	engine, err := dockerEngineVersion()
	if err != nil {
		fmt.Fprintf(stderr, "composepreflight: docker engine: %v\n", err)
		return 1
	}
	compose, err := composeVersion()
	if err != nil {
		fmt.Fprintf(stderr, "composepreflight: docker compose: %v\n", err)
		return 1
	}
	if !engineOK(engine) {
		fmt.Fprintf(stderr, "composepreflight: Docker Engine %s is below 24.0 (OD-020)\n", engine)
		return 1
	}
	if !composeOK(compose) {
		fmt.Fprintf(stderr, "composepreflight: Compose %s is below 2.24 (OD-020)\n", compose)
		return 1
	}
	fmt.Fprintf(stdout, "composepreflight: docker %s compose %s (OD-020 min 24 / 2.24)\n", engine, compose)
	return 0
}

func dockerEngineVersion() (string, error) {
	out, err := exec.Command("docker", "version", "--format", "{{.Server.Version}}").Output()
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(string(out)), nil
}

func composeVersion() (string, error) {
	out, err := exec.Command("docker", "compose", "version", "--short").Output()
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(string(out)), nil
}

func engineOK(v string) bool {
	maj, _, _, ok := parseVersion(v)
	return ok && maj >= minEngineMajor
}

func composeOK(v string) bool {
	maj, min, _, ok := parseVersion(v)
	if !ok {
		return false
	}
	if maj > minComposeMajor {
		return true
	}
	return maj == minComposeMajor && min >= minComposeMinor
}

func parseVersion(v string) (major, minor, patch int, ok bool) {
	v = strings.TrimPrefix(v, "v")
	if i := strings.IndexAny(v, "+-"); i >= 0 {
		v = v[:i]
	}
	parts := strings.Split(v, ".")
	if len(parts) < 2 {
		return 0, 0, 0, false
	}
	var err error
	major, err = strconv.Atoi(parts[0])
	if err != nil {
		return 0, 0, 0, false
	}
	minor, err = strconv.Atoi(parts[1])
	if err != nil {
		return 0, 0, 0, false
	}
	if len(parts) > 2 {
		patch, _ = strconv.Atoi(parts[2])
	}
	return major, minor, patch, true
}
