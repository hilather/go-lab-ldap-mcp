package observability_test

import (
	"bytes"
	"strings"
	"testing"

	"github.com/hilather/go-lab-ldap-mcp/internal/observability"
)

func TestStartupLoggerAndWriteVersion(t *testing.T) {
	t.Setenv("LABLDAP_LOG_FORMAT", "json")
	var logs, ver bytes.Buffer
	info, logger := observability.StartupLogger(&logs, "labldap")
	if logger == nil {
		t.Fatal("nil logger")
	}
	if info.Component != "labldap" || info.Version == "" {
		t.Fatalf("info = %+v", info)
	}
	if !strings.Contains(logs.String(), `"component":"labldap"`) || !strings.Contains(logs.String(), `"version":`) {
		t.Fatalf("startup log = %s", logs.String())
	}
	observability.WriteVersion(&ver, info)
	if !strings.Contains(ver.String(), "component=labldap") || !strings.Contains(ver.String(), "version=") {
		t.Fatalf("version = %q", ver.String())
	}
}
