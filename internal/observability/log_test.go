package observability_test

import (
	"bytes"
	"log/slog"
	"strings"
	"testing"

	"github.com/hilather/go-lab-ldap-mcp/internal/observability"
)

func TestNewLoggerJSONIncludesComponentAndVersion(t *testing.T) {
	t.Parallel()
	var buf bytes.Buffer
	info := observability.BuildInfo{Version: "test-ver", Revision: "abc123", Component: "labldap"}
	log := observability.NewLogger(&buf, observability.FormatJSON, info)
	log.Info("starting")
	out := buf.String()
	for _, want := range []string{`"component":"labldap"`, `"version":"test-ver"`, `"msg":"starting"`} {
		if !strings.Contains(out, want) {
			t.Fatalf("missing %s in %s", want, out)
		}
	}
}

func TestNewLoggerTextIncludesFields(t *testing.T) {
	t.Parallel()
	var buf bytes.Buffer
	info := observability.BuildInfo{Version: "test-ver", Revision: "abc123", Component: "labldap-bootstrap"}
	log := observability.NewLogger(&buf, observability.FormatText, info)
	log.Info("starting")
	out := buf.String()
	for _, want := range []string{"component=labldap-bootstrap", "version=test-ver"} {
		if !strings.Contains(out, want) {
			t.Fatalf("missing %s in %s", want, out)
		}
	}
}

func TestCurrentBuildHasNonEmptyFields(t *testing.T) {
	t.Parallel()
	info := observability.CurrentBuild("labldap")
	if info.Component != "labldap" {
		t.Fatalf("component = %q", info.Component)
	}
	if info.Version == "" || info.Revision == "" || info.Time == "" {
		t.Fatalf("empty build field: %+v", info)
	}
	if info.LogValue().Kind() != slog.KindGroup {
		t.Fatal("LogValue should be a group")
	}
}

func TestNormalizeFormat(t *testing.T) {
	t.Parallel()
	if observability.NormalizeFormat("JSON") != observability.FormatJSON {
		t.Fatal("JSON")
	}
	if observability.NormalizeFormat("") != observability.FormatText {
		t.Fatal("default")
	}
}
