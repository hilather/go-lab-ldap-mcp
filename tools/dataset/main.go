// labldap-dataset writes small or medium LabScenario YAML for soak and
// bootstrap qualification. Passwords are file references, never inline.
package main

import (
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

func main() {
	users := flag.Int("users", 50, "number of users")
	groups := flag.Int("groups", 5, "number of groups")
	out := flag.String("out", "", "output YAML path")
	passwordFile := flag.String("password-file", "secrets/user-alice", "shared passwordFile for generated users")
	name := flag.String("name", "soak-lab", "metadata.name")
	flag.Parse()
	if *out == "" {
		fmt.Fprintln(os.Stderr, "dataset: --out is required")
		os.Exit(2)
	}
	if *users < 1 || *groups < 1 {
		fmt.Fprintln(os.Stderr, "dataset: users and groups must be >= 1")
		os.Exit(2)
	}
	body, err := generate(*name, *users, *groups, *passwordFile)
	if err != nil {
		fmt.Fprintf(os.Stderr, "dataset: %v\n", err)
		os.Exit(1)
	}
	if err := os.MkdirAll(filepath.Dir(*out), 0o755); err != nil {
		fmt.Fprintf(os.Stderr, "dataset: %v\n", err)
		os.Exit(1)
	}
	if err := os.WriteFile(*out, []byte(body), 0o600); err != nil {
		fmt.Fprintf(os.Stderr, "dataset: %v\n", err)
		os.Exit(1)
	}
	fmt.Printf("dataset: wrote %s users=%d groups=%d\n", *out, *users, *groups)
}

func generate(name string, users, groups int, passwordFile string) (string, error) {
	if strings.TrimSpace(name) == "" {
		return "", fmt.Errorf("name is required")
	}
	if users < 1 || groups < 1 {
		return "", fmt.Errorf("users and groups must be >= 1")
	}
	if users < groups {
		return "", fmt.Errorf("need at least one user per group")
	}
	var b strings.Builder
	b.WriteString("apiVersion: labldap.dev/v1alpha1\n")
	b.WriteString("kind: LabScenario\n")
	b.WriteString("metadata:\n")
	fmt.Fprintf(&b, "  name: %s\n", name)
	b.WriteString("spec:\n")
	b.WriteString("  directory:\n")
	b.WriteString("    suffix: \"dc=example,dc=test\"\n")
	b.WriteString("    peopleRDN: \"ou=people\"\n")
	b.WriteString("    groupsRDN: \"ou=groups\"\n")
	b.WriteString("  lifecycle:\n")
	b.WriteString("    storageMode: ephemeral\n")
	b.WriteString("    startupMode: merge\n")
	b.WriteString("    softReset: true\n")
	b.WriteString("  transport:\n")
	b.WriteString("    insecureLabMode: false\n")
	b.WriteString("    ldap: { enabled: true, port: 3389 }\n")
	b.WriteString("    ldaps: { enabled: true, port: 3636 }\n")
	b.WriteString("    startTLS: true\n")
	b.WriteString("    allowCleartextBind: false\n")
	b.WriteString("  management:\n")
	b.WriteString("    listen: \"127.0.0.1:8443\"\n")
	b.WriteString("    tls: { mode: generated }\n")
	b.WriteString("  runtimeAccount:\n")
	b.WriteString("    id: labldap-runtime\n")
	b.WriteString("    passwordFile: secrets/runtime-ldap\n")
	b.WriteString("  tokens:\n")
	b.WriteString("    - id: admin\n")
	b.WriteString("      secretFile: secrets/token-admin\n")
	b.WriteString("      scopes: [directory:read, directory:write, lab:reset, lab:export, schema:read, audit:read]\n")
	b.WriteString("  users:\n")
	for i := 1; i <= users; i++ {
		id := fmt.Sprintf("u%05d", i)
		fmt.Fprintf(&b, "    - id: %s\n      uid: %s\n      passwordFile: %s\n      enabled: true\n", id, id, passwordFile)
	}
	b.WriteString("  groups:\n")
	per := users / groups
	for g := 1; g <= groups; g++ {
		fmt.Fprintf(&b, "    - id: g%04d\n      members:\n", g)
		start := (g-1)*per + 1
		end := start + per - 1
		if g == groups {
			end = users
		}
		for u := start; u <= end; u++ {
			fmt.Fprintf(&b, "        - user: u%05d\n", u)
		}
	}
	return b.String(), nil
}
