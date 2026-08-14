package main

import (
	"bytes"
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestGenerateNoOverwriteNoPrint(t *testing.T) {
	dir := t.TempDir()
	var out bytes.Buffer
	written, err := generate(dir, false, false, &out)
	if err != nil {
		t.Fatal(err)
	}
	if len(written) != 5 {
		t.Fatalf("written=%v", written)
	}
	st, err := os.Stat(dir)
	if err != nil {
		t.Fatal(err)
	}
	if st.Mode().Perm() != 0o700 {
		t.Fatalf("dir mode %o", st.Mode().Perm())
	}
	files := defaultFiles(dir)
	for _, p := range []string{files.DirectoryEnv, files.DMPassword, files.RuntimeLDAP, files.UserAlice, files.TokenAdmin} {
		info, err := os.Stat(p)
		if err != nil {
			t.Fatal(err)
		}
		if info.Mode().Perm() != 0o600 {
			t.Fatalf("%s mode %o", p, info.Mode().Perm())
		}
		raw, err := os.ReadFile(p)
		if err != nil {
			t.Fatal(err)
		}
		if bytes.Contains(out.Bytes(), bytes.TrimSpace(raw)) {
			t.Fatalf("secret value printed for %s", p)
		}
		if !strings.Contains(out.String(), "wrote "+p) {
			t.Fatalf("missing write notice for %s: %s", p, out.String())
		}
	}
	env := readFile(t, files.DirectoryEnv)
	if !strings.HasPrefix(env, "DS_DM_PASSWORD=") || strings.Contains(env, " ") {
		t.Fatalf("directory.env = %q", env)
	}
	pw := strings.TrimPrefix(strings.TrimSpace(env), "DS_DM_PASSWORD=")
	if strings.TrimSpace(readFile(t, files.DMPassword)) != pw {
		t.Fatal("dm.pw must match directory.env")
	}
	tok := strings.TrimSpace(readFile(t, files.TokenAdmin))
	raw, err := hex.DecodeString(tok)
	if err != nil {
		t.Fatal(err)
	}
	if len(raw) < tokenBytes {
		t.Fatalf("token entropy %d bytes", len(raw))
	}

	out.Reset()
	second, err := generate(dir, false, false, &out)
	if err != nil {
		t.Fatal(err)
	}
	if len(second) != 0 {
		t.Fatalf("overwrite without --force: %v", second)
	}
	if !strings.Contains(out.String(), "skipped") {
		t.Fatalf("expected skip notices: %s", out.String())
	}
	if strings.TrimSpace(readFile(t, files.TokenAdmin)) != tok {
		t.Fatal("token overwritten without --force")
	}
}

func TestGeneratePrintAndForce(t *testing.T) {
	dir := t.TempDir()
	var out bytes.Buffer
	if _, err := generate(dir, false, true, &out); err != nil {
		t.Fatal(err)
	}
	tok := strings.TrimSpace(readFile(t, defaultFiles(dir).TokenAdmin))
	if !strings.Contains(out.String(), "value="+tok) {
		t.Fatalf("expected printed token: %s", out.String())
	}
	out.Reset()
	if _, err := generate(dir, true, false, &out); err != nil {
		t.Fatal(err)
	}
	if strings.TrimSpace(readFile(t, defaultFiles(dir).TokenAdmin)) == tok {
		t.Fatal("--force must rotate token")
	}
}

func TestHalfPairRefused(t *testing.T) {
	dir := t.TempDir()
	files := defaultFiles(dir)
	if err := os.WriteFile(files.DMPassword, []byte("old-dm-password-value\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	var out bytes.Buffer
	if _, err := generate(dir, false, false, &out); err == nil {
		t.Fatal("expected KD-R20 pair-split error")
	} else if !strings.Contains(err.Error(), "pair split") {
		t.Fatalf("err=%v", err)
	}
	if strings.TrimSpace(readFile(t, files.DMPassword)) != "old-dm-password-value" {
		t.Fatal("existing dm.pw must be left unchanged")
	}
	if fileExists(files.DirectoryEnv) {
		t.Fatal("must not write directory.env when dm.pw is the only half")
	}

	if err := os.Remove(files.DMPassword); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(files.DirectoryEnv, []byte("DS_DM_PASSWORD=only-env-password\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	out.Reset()
	if _, err := generate(dir, false, false, &out); err == nil {
		t.Fatal("expected pair-split when only directory.env exists")
	}
	if fileExists(files.DMPassword) {
		t.Fatal("must not write dm.pw from a half pair")
	}
}

func TestRunHelp(t *testing.T) {
	var stdout, stderr bytes.Buffer
	if code := run([]string{"-h"}, &stdout, &stderr); code != 0 {
		t.Fatalf("code=%d stderr=%s", code, stderr.String())
	}
	if !strings.Contains(stdout.String(), "labldap-setup-secrets") {
		t.Fatalf("help=%s", stdout.String())
	}
}

func readFile(t *testing.T, path string) string {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	_ = filepath.Dir(path)
	return string(b)
}
