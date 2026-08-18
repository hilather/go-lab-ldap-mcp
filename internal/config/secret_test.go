package config_test

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/hilather/go-lab-ldap-mcp/internal/apperr"
	"github.com/hilather/go-lab-ldap-mcp/internal/config"
)

func TestFileSecretResolver(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "pw")
	if err := os.WriteFile(p, []byte("hunter2\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	got, err := config.FileSecretResolver().Resolve(t.Context(), "spec.users[0].passwordFile", p)
	if err != nil {
		t.Fatal(err)
	}
	if got.Value.Reveal() != "hunter2" {
		t.Fatalf("reveal = %q", got.Value.Reveal())
	}
	if got.Digest == "" || got.Digest == got.Value.Reveal() {
		t.Fatalf("digest = %q", got.Digest)
	}
	if strings.Contains(fmt.Sprint(got.Value), "hunter2") || strings.Contains(fmt.Sprintf("%#v", got.Value), "hunter2") {
		t.Fatal("secret stringified")
	}
	again, err := config.FileSecretResolver().Resolve(t.Context(), "spec.users[0].passwordFile", p)
	if err != nil {
		t.Fatal(err)
	}
	if again.Digest != got.Digest {
		t.Fatal("digest not stable")
	}
}

func TestDirSecretResolverPrefersConfigDir(t *testing.T) {
	cfgDir := t.TempDir()
	cwd := t.TempDir()
	if err := os.WriteFile(filepath.Join(cfgDir, "token"), []byte("from-config"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(cwd, "token"), []byte("from-cwd"), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Chdir(cwd)
	got, err := config.DirSecretResolver(cfgDir).Resolve(t.Context(), "spec.tokens[0].secretFile", "token")
	if err != nil {
		t.Fatal(err)
	}
	if got.Value.Reveal() != "from-config" {
		t.Fatalf("resolved %q, want from-config", got.Value.Reveal())
	}
}

func TestSecretUnreadableHasPathNotContent(t *testing.T) {
	err := mustErr(t, func() error {
		_, e := config.FileSecretResolver().Resolve(t.Context(), "spec.runtimeAccount.passwordFile", "/no/such/secret")
		return e
	})
	apperr.Assert(t, err).Code(apperr.CodeConfiguration).FieldPath("spec.runtimeAccount.passwordFile")
	if strings.Contains(err.Error(), "hunter2") {
		t.Fatal(err)
	}
}

func mustErr(t *testing.T, fn func() error) error {
	t.Helper()
	err := fn()
	if err == nil {
		t.Fatal("expected error")
	}
	return err
}
