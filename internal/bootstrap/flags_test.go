package bootstrap

import (
	"strings"
	"testing"
	"time"
)

func TestParseArgsPasswordFlagRejected(t *testing.T) {
	for _, args := range [][]string{
		{"--config", "x.yaml", "--directory-manager-password", "secret"},
		{"--config", "x.yaml", "--directory-manager-password=secret"},
	} {
		_, err := ParseArgs("apply", args)
		if err == nil {
			t.Fatalf("expected usage error for %v", args)
		}
		if _, ok := err.(*UsageError); !ok {
			t.Fatalf("want UsageError, got %T %v", err, err)
		}
		if !strings.Contains(err.Error(), "password-file") {
			t.Fatalf("error = %v", err)
		}
	}
}

func TestParseArgsApplyRequiresPasswordFile(t *testing.T) {
	_, err := ParseArgs("apply", []string{"--config", "x.yaml"})
	if err == nil {
		t.Fatal("expected missing password file")
	}
	if !strings.Contains(err.Error(), "password-file") {
		t.Fatalf("error = %v", err)
	}
}

func TestParseArgsPlanOptionalPassword(t *testing.T) {
	opt, err := ParseArgs("plan", []string{"--config", "x.yaml", "--deadline", "5s"})
	if err != nil {
		t.Fatal(err)
	}
	if opt.ConfigPath != "x.yaml" || opt.Deadline != 5*time.Second {
		t.Fatalf("%+v", opt)
	}
}

func TestParseArgsUnknownFlag(t *testing.T) {
	_, err := ParseArgs("apply", []string{"--config", "x.yaml", "--directory-manager-password-file", "pw", "--nope"})
	if err == nil {
		t.Fatal("expected unknown flag")
	}
}
