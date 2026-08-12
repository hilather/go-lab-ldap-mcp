package observability_test

import (
	"bytes"
	"encoding/json"
	"fmt"
	"log/slog"
	"strings"
	"testing"

	"github.com/hilather/go-lab-ldap-mcp/internal/observability"
)

const leak = "super-secret-lab-token-value-32chars!!"

func TestSecretDoesNotStringify(t *testing.T) {
	t.Parallel()
	s := observability.Secret(leak)

	if got := s.String(); strings.Contains(got, leak) {
		t.Fatalf("String leaked: %q", got)
	}
	if got := fmt.Sprintf("%s", s); strings.Contains(got, leak) {
		t.Fatalf("fmt %%s leaked: %q", got)
	}
	if got := fmt.Sprintf("%v", s); strings.Contains(got, leak) {
		t.Fatalf("fmt %%v leaked: %q", got)
	}
	if got := fmt.Sprintf("%#v", s); strings.Contains(got, leak) {
		t.Fatalf("fmt %%#v leaked: %q", got)
	}
	if got := fmt.Sprintf("%+v", s); strings.Contains(got, leak) {
		t.Fatalf("fmt %%+v leaked: %q", got)
	}
}

func TestSecretJSONAndLog(t *testing.T) {
	t.Parallel()
	s := observability.Secret(leak)

	raw, err := json.Marshal(s)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(raw), leak) {
		t.Fatalf("json leaked: %s", raw)
	}

	var buf bytes.Buffer
	log := slog.New(slog.NewJSONHandler(&buf, nil))
	log.Info("bind", slog.Any("password", s), slog.String("component", "test"))
	if strings.Contains(buf.String(), leak) {
		t.Fatalf("slog leaked: %s", buf.String())
	}
	if !strings.Contains(buf.String(), "[redacted]") {
		t.Fatalf("slog missing redaction marker: %s", buf.String())
	}
}

func TestSecretRevealIsExplicit(t *testing.T) {
	t.Parallel()
	s := observability.Secret(leak)
	if s.Reveal() != leak {
		t.Fatalf("Reveal() = %q", s.Reveal())
	}
}
