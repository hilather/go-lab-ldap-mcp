package config_test

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/hilather/go-lab-ldap-mcp/internal/apperr"
	"github.com/hilather/go-lab-ldap-mcp/internal/config"
	"github.com/hilather/go-lab-ldap-mcp/internal/config/v1alpha1"
)

func exampleYAML(t *testing.T) []byte {
	t.Helper()
	p := filepath.Join("..", "..", "config", "examples", "example-lab.yaml")
	b, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func TestParseExample(t *testing.T) {
	got, err := config.Parse(exampleYAML(t), "example-lab.yaml")
	if err != nil {
		t.Fatal(err)
	}
	if got.APIVersion != v1alpha1.APIVersion || got.Kind != v1alpha1.Kind {
		t.Fatalf("dispatch = %s %s", got.APIVersion, got.Kind)
	}
	if got.Metadata.Name != "example-lab" {
		t.Fatalf("name = %q", got.Metadata.Name)
	}
	if got.Spec.Directory.Suffix != "dc=example,dc=test" {
		t.Fatalf("suffix = %q", got.Spec.Directory.Suffix)
	}
	if got.Spec.RuntimeAccount.PasswordFile == "" {
		t.Fatal("runtime password path missing")
	}
}

func TestLoadConvertsSecretRefs(t *testing.T) {
	p, err := config.Load(t.Context(), exampleYAML(t), "example-lab.yaml", config.LoadOptions{Caller: config.CallerCLI})
	if err != nil {
		t.Fatal(err)
	}
	if p.Input.RuntimeAccount.Password.File != "/run/secrets/runtime-ldap" {
		t.Fatalf("runtime secret = %#v", p.Input.RuntimeAccount.Password)
	}
	if p.Input.Users[0].Password.File != "/run/secrets/user-alice" {
		t.Fatalf("user secret = %#v", p.Input.Users[0].Password)
	}
	if p.Input.Tokens[0].Secret.File != "/run/secrets/token-admin" {
		t.Fatalf("token secret = %#v", p.Input.Tokens[0].Secret)
	}
}

func TestUnsupportedVersionAndKind(t *testing.T) {
	src := []byte("apiVersion: labldap.dev/v9\nkind: Other\nmetadata:\n  name: x\nspec: {}\n")
	err := config.Validate(src, "bad.yaml")
	if err == nil {
		t.Fatal("expected error")
	}
	apperr.Assert(t, err).Code(apperr.CodeConfiguration)
	fields := mustFields(t, err)
	if !hasCode(fields, "unsupported_version") || !hasCode(fields, "unsupported_kind") {
		t.Fatalf("fields = %#v", fields)
	}
}

func TestUnknownField(t *testing.T) {
	src := []byte("apiVersion: labldap.dev/v1alpha1\nkind: LabScenario\nmetadata:\n  name: x\nspec:\n  notARealField: 1\n")
	err := config.Validate(src, "unknown.yaml")
	if err == nil {
		t.Fatal("expected error")
	}
	if !hasCode(mustFields(t, err), "unknown_field") {
		t.Fatalf("fields = %#v", mustFields(t, err))
	}
}

func TestDuplicateKey(t *testing.T) {
	src := []byte("apiVersion: labldap.dev/v1alpha1\nkind: LabScenario\nmetadata:\n  name: x\n  name: y\nspec: {}\n")
	err := config.Validate(src, "dup.yaml")
	if err == nil {
		t.Fatal("expected error")
	}
	if !hasCode(mustFields(t, err), "duplicate_key") {
		t.Fatalf("fields = %#v", mustFields(t, err))
	}
}

func TestTrailingDocument(t *testing.T) {
	src := []byte("apiVersion: labldap.dev/v1alpha1\nkind: LabScenario\nmetadata:\n  name: x\nspec: {}\n---\napiVersion: labldap.dev/v1alpha1\nkind: LabScenario\nmetadata:\n  name: y\nspec: {}\n")
	err := config.Validate(src, "trail.yaml")
	if err == nil {
		t.Fatal("expected error")
	}
	if !hasCode(mustFields(t, err), "trailing_document") {
		t.Fatalf("fields = %#v", mustFields(t, err))
	}
}

func TestEmptyFile(t *testing.T) {
	err := config.Validate([]byte("   \n"), "empty.yaml")
	if err == nil {
		t.Fatal("expected error")
	}
	if !hasCode(mustFields(t, err), "empty") {
		t.Fatalf("fields = %#v", mustFields(t, err))
	}
}

func TestSecretValueAbsentFromDiagnostics(t *testing.T) {
	const canary = "super-secret-lab-token-value-32chars!!"
	src := []byte("apiVersion: labldap.dev/v1alpha1\nkind: LabScenario\nmetadata:\n  name: x\nspec:\n  leaked: " + canary + "\n")
	err := config.Validate(src, "leak.yaml")
	if err == nil {
		t.Fatal("expected error")
	}
	if strings.Contains(err.Error(), canary) {
		t.Fatalf("error leaked secret: %v", err)
	}
	var e *apperr.Error
	if !errors.As(err, &e) {
		t.Fatal("not apperr")
	}
	if strings.Contains(e.PublicMessage(), canary) {
		t.Fatal("public message leaked secret")
	}
	for _, f := range e.Fields() {
		if strings.Contains(f.Message, canary) || strings.Contains(f.Path, canary) {
			t.Fatalf("field leaked secret: %#v", f)
		}
	}
}

func TestNoRawEntriesKey(t *testing.T) {
	src := []byte("apiVersion: labldap.dev/v1alpha1\nkind: LabScenario\nmetadata:\n  name: x\nspec:\n  rawEntries: []\n")
	err := config.Validate(src, "raw.yaml")
	if err == nil {
		t.Fatal("rawEntries must be rejected")
	}
	if !hasCode(mustFields(t, err), "unknown_field") {
		t.Fatalf("fields = %#v", mustFields(t, err))
	}
}

func mustFields(t *testing.T, err error) []apperr.Field {
	t.Helper()
	var e *apperr.Error
	if !errors.As(err, &e) {
		t.Fatalf("not apperr: %v", err)
	}
	return e.Fields()
}

func hasCode(fields []apperr.Field, code string) bool {
	for _, f := range fields {
		if f.Code == code {
			return true
		}
	}
	return false
}
