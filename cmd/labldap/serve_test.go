package main

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/hilather/go-lab-ldap-mcp/internal/directory"
)

func TestParseServeFlags(t *testing.T) {
	t.Setenv("LABLDAP_LDAP_URL", "")
	t.Setenv("LABLDAP_DIRECTORY_CA_FILE", "")
	t.Setenv("LABLDAP_DIRECTORY_HOST", "")
	f, err := parseServeFlags([]string{"--config", "x.yaml", "--ldap-url", "ldaps://127.0.0.1:3636", "--directory-ca-file", "/ca.pem", "--directory-host", "dir.example"})
	if err != nil {
		t.Fatal(err)
	}
	if f.configPath != "x.yaml" || f.ldapURL != "ldaps://127.0.0.1:3636" || f.caFile != "/ca.pem" || f.dirHost != "dir.example" {
		t.Fatalf("%+v", f)
	}
	if _, err := parseServeFlags(nil); err == nil {
		t.Fatal("expected required")
	}
	if _, err := parseServeFlags([]string{"--placeholder"}); err != nil {
		t.Fatal(err)
	}
	if _, err := parseServeFlags([]string{"--help"}); err != errServeHelp {
		t.Fatalf("help: %v", err)
	}
}

func TestLDAPClientConfigFromExample(t *testing.T) {
	path := filepath.Join("..", "..", "config", "examples", "example-lab.yaml")
	src, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	built, err := compileControl(context.Background(), path)
	if err != nil {
		t.Fatalf("compile: %v", err)
	}
	_ = src
	cfg, err := ldapClientConfig(built, serveFlags{ldapURL: "ldaps://127.0.0.1:3636", caFile: "/tmp/ca.pem", dirHost: "localhost"}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Address != "127.0.0.1:3636" || cfg.Transport != directory.TransportLDAPS {
		t.Fatalf("%+v", cfg)
	}
	if cfg.BindDN == "" || cfg.CAFile != "/tmp/ca.pem" || cfg.ServerName != "localhost" {
		t.Fatalf("%+v", cfg)
	}
	if cfg.BindPassword.Reveal() == "" {
		t.Fatal("runtime password missing")
	}
}
