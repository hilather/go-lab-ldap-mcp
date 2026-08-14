package observability_test

import (
	"bytes"
	"fmt"
	"log/slog"
	"net/http"
	"path/filepath"
	"strings"
	"testing"

	"github.com/hilather/go-lab-ldap-mcp/internal/observability"
)

func TestCanaryLeakFailsScan(t *testing.T) {
	t.Parallel()
	path := filepath.Join("testdata", "canary-leak.txt")
	findings, err := observability.ScanFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(findings) == 0 {
		t.Fatal("canary fixture must fail the leak scan")
	}
	report := observability.ReportFindings(findings)
	if strings.Contains(report, observability.CanarySecret) {
		t.Fatalf("report echoed canary: %s", report)
	}
	var sawCanary, sawBearer bool
	for _, f := range findings {
		if f.Rule == "canary-secret" {
			sawCanary = true
		}
		if f.Rule == "authorization-bearer" {
			sawBearer = true
		}
	}
	if !sawCanary || !sawBearer {
		t.Fatalf("findings = %+v", findings)
	}
}

func TestCleanLogsHaveNoGeneratedSecrets(t *testing.T) {
	t.Parallel()
	token := "lab-generated-token-value-32xxxx"
	seed := "lab-generated-seed-password-12"
	session := "lab-generated-session-id-32xxxx"
	bind := "lab-generated-bind-password-12"

	h := http.Header{}
	h.Set("Authorization", "Bearer "+token)
	h.Set("Cookie", "labldap_session="+session)
	safe := observability.SanitizeHeaders(h)

	var buf bytes.Buffer
	log := slog.New(slog.NewJSONHandler(&buf, nil))
	log.Info("login",
		slog.Any("token", observability.Secret(token)),
		slog.Any("password", observability.Secret(seed)),
		slog.Any("session", observability.Secret(session)),
		slog.Any("bind", observability.Secret(bind)),
		slog.String("authorization", observability.SanitizeHeader("Authorization", h.Get("Authorization"))),
		slog.String("cookie", observability.SanitizeHeader("Cookie", h.Get("Cookie"))),
	)
	fmt.Fprintf(&buf, "headers authorization=%s cookie=%s\n", safe.Get("Authorization"), safe.Get("Cookie"))

	findings, err := observability.ScanReader(&buf, token, seed, session, bind)
	if err != nil {
		t.Fatal(err)
	}
	if len(findings) != 0 {
		t.Fatalf("clean log leaked: %s\n%s", observability.ReportFindings(findings), buf.String())
	}
}

func TestScanDetectsSuppliedSecret(t *testing.T) {
	t.Parallel()
	secret := "lab-scan-detect-me-32-characters!"
	findings, err := observability.ScanReader(strings.NewReader("oops "+secret+"\n"), secret)
	if err != nil {
		t.Fatal(err)
	}
	if len(findings) == 0 {
		t.Fatal("expected supplied secret to fail the scan")
	}
	if strings.Contains(observability.ReportFindings(findings), secret) {
		t.Fatal("report contained secret")
	}
}
