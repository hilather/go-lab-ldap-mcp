package ds389

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestRunnerJSONUsesPasswordFileNotArgv(t *testing.T) {
	dir := t.TempDir()
	argvPath := filepath.Join(dir, "argv.txt")
	bin := filepath.Join(dir, "dsconf")
	script := "#!/bin/sh\nprintf '%s\\0' \"$@\" > \"$LABLDAP_ARGV_OUT\"\nprintf '%s\\n' '{\"type\":\"list\",\"items\":[]}'\n"
	if err := os.WriteFile(bin, []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	pwd := filepath.Join(dir, "dm.pw")
	if err := os.WriteFile(pwd, []byte("super-secret-dm\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("LABLDAP_ARGV_OUT", argvPath)
	r := Runner{Bin: bin}
	out, err := r.JSON(t.Context(), pwd, "localhost", []string{"backend", "suffix", "list"})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(out), `"type"`) {
		t.Fatalf("stdout = %s", out)
	}
	raw, err := os.ReadFile(argvPath)
	if err != nil {
		t.Fatal(err)
	}
	argv := string(raw)
	if strings.Contains(argv, "super-secret-dm") {
		t.Fatal("password leaked onto argv")
	}
	if strings.Contains(argv, "sh") && strings.Contains(argv, "-c") {
		t.Fatal("runner used sh -c")
	}
	if !strings.Contains(argv, "-y") || !strings.Contains(argv, pwd) {
		t.Fatalf("missing -y password file in %q", argv)
	}
	if !strings.Contains(argv, "-j") {
		t.Fatal("missing --json/-j")
	}
}

func TestRunnerRejectsEmptyPasswordFile(t *testing.T) {
	_, err := Runner{}.JSON(context.Background(), "", "localhost", []string{"backend", "suffix", "list"})
	if err == nil {
		t.Fatal("expected error")
	}
}
