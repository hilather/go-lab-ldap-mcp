// labldap-setup-secrets generates gitignored lab secret files (T-112, KD-R20).
package main

import (
	"crypto/rand"
	"encoding/hex"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
)

const (
	tokenBytes    = 32
	passwordBytes = 24
	usageText     = `labldap-setup-secrets — generate lab secret files

Writes Directory Manager env_file (KD-R20), bootstrap password file, runtime
LDAP password, seed user password, and management token. All files are 0600.
Control reads them via Compose secrets (uid 65532, mode 0400), not world-
readable bind mounts. Existing files are left unchanged unless --force is
set. Secret values are not printed unless --print is set. The KD-R20 pair
directory.env + dm.pw must both exist or both be missing.

Usage:
  labldap-setup-secrets [--dir secrets] [--force] [--print]
`
)

type files struct {
	DirectoryEnv string
	DMPassword   string
	RuntimeLDAP  string
	UserAlice    string
	TokenAdmin   string
}

func defaultFiles(dir string) files {
	return files{
		DirectoryEnv: filepath.Join(dir, "directory.env"),
		DMPassword:   filepath.Join(dir, "dm.pw"),
		RuntimeLDAP:  filepath.Join(dir, "runtime-ldap"),
		UserAlice:    filepath.Join(dir, "user-alice"),
		TokenAdmin:   filepath.Join(dir, "token-admin"),
	}
}

func main() {
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr))
}

func run(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("setupsecrets", flag.ContinueOnError)
	fs.SetOutput(stderr)
	dir := fs.String("dir", "secrets", "output directory (created with mode 0700)")
	force := fs.Bool("force", false, "overwrite existing secret files")
	printVals := fs.Bool("print", false, "print secret values (off by default)")
	if err := fs.Parse(args); err != nil {
		if err == flag.ErrHelp {
			fmt.Fprint(stdout, usageText)
			return 0
		}
		return 2
	}
	written, err := generate(*dir, *force, *printVals, stdout)
	if err != nil {
		fmt.Fprintf(stderr, "setupsecrets: %v\n", err)
		return 1
	}
	if len(written) == 0 {
		fmt.Fprintln(stdout, "setupsecrets: no files written")
	}
	return 0
}

func generate(dir string, force, printVals bool, stdout io.Writer) ([]string, error) {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, err
	}
	if err := os.Chmod(dir, 0o700); err != nil {
		return nil, err
	}
	out := defaultFiles(dir)
	var written []string

	dm, err := ensurePasswordPair(out.DirectoryEnv, out.DMPassword, force, printVals, stdout)
	if err != nil {
		return written, err
	}
	written = append(written, dm...)

	for _, item := range []struct {
		path string
		n    int
		mode os.FileMode
	}{
		{out.RuntimeLDAP, passwordBytes, 0o600},
		{out.UserAlice, passwordBytes, 0o600},
		{out.TokenAdmin, tokenBytes, 0o600},
	} {
		ok, err := writeSecretFile(item.path, item.n, item.mode, force, printVals, stdout)
		if err != nil {
			return written, err
		}
		if ok {
			written = append(written, item.path)
		}
	}
	return written, nil
}

func ensurePasswordPair(envPath, dmPath string, force, printVals bool, stdout io.Writer) ([]string, error) {
	var written []string
	envExists := fileExists(envPath)
	dmExists := fileExists(dmPath)
	if envExists != dmExists && !force {
		return nil, fmt.Errorf("KD-R20 pair split: %s and %s must both exist or both be missing (use --force to replace both)", envPath, dmPath)
	}
	if envExists && dmExists && !force {
		fmt.Fprintf(stdout, "skipped %s (exists)\n", envPath)
		fmt.Fprintf(stdout, "skipped %s (exists)\n", dmPath)
		return nil, nil
	}
	pw, err := randomHex(passwordBytes)
	if err != nil {
		return nil, err
	}
	if err := writeFile(envPath, []byte("DS_DM_PASSWORD="+pw+"\n"), 0o600); err != nil {
		return nil, err
	}
	reportWrite(stdout, envPath, pw, printVals)
	written = append(written, envPath)
	if err := writeFile(dmPath, []byte(pw+"\n"), 0o600); err != nil {
		return nil, err
	}
	reportWrite(stdout, dmPath, pw, printVals)
	written = append(written, dmPath)
	return written, nil
}

func writeSecretFile(path string, n int, mode os.FileMode, force, printVals bool, stdout io.Writer) (bool, error) {
	if fileExists(path) && !force {
		fmt.Fprintf(stdout, "skipped %s (exists)\n", path)
		return false, nil
	}
	val, err := randomHex(n)
	if err != nil {
		return false, err
	}
	if err := writeFile(path, []byte(val+"\n"), mode); err != nil {
		return false, err
	}
	reportWrite(stdout, path, val, printVals)
	return true, nil
}

func reportWrite(w io.Writer, path, value string, printVals bool) {
	if printVals {
		fmt.Fprintf(w, "wrote %s value=%s\n", path, value)
		return
	}
	fmt.Fprintf(w, "wrote %s\n", path)
}

func randomHex(n int) (string, error) {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

func writeFile(path string, data []byte, mode os.FileMode) error {
	if err := os.WriteFile(path, data, mode); err != nil {
		return err
	}
	return os.Chmod(path, mode)
}

func fileExists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}

func readEnvPassword(path string) (string, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	for _, line := range strings.Split(string(b), "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "DS_DM_PASSWORD=") {
			return strings.TrimPrefix(line, "DS_DM_PASSWORD="), nil
		}
	}
	return "", fmt.Errorf("%s: missing DS_DM_PASSWORD", path)
}
