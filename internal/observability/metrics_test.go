package observability_test

import (
	"bytes"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/hilather/go-lab-ldap-mcp/internal/observability"
)

func TestMetricsBoundedLabelsAndBuildInfo(t *testing.T) {
	t.Parallel()
	reg := observability.NewRegistry(observability.BuildInfo{Version: "dev", Revision: "abc123", Component: "labldap"})
	reg.ObserveHTTP("GET", observability.RouteTemplate("GET", "/api/v1/users/alice"), observability.StatusClass(200), 12*time.Millisecond)
	reg.ObserveHTTP("GET", observability.RouteTemplate("GET", "/api/v1/users/bob"), observability.StatusClass(404), time.Millisecond)
	reg.ObserveMCP("ldap_search_entries", "ok")
	reg.ObserveAuth("success", "ok")
	reg.ObserveAuth("failure", "invalid")
	reg.ObserveReset("success")
	reg.ObserveExport("failure")
	reg.SetLDAPPool(1, 2, 16, 0)
	reg.ObserveLDAPDial(true)
	reg.ObserveLDAPDial(false)
	reg.ObserveLDAPEvict("idle")
	reg.ObserveLDAPWaitTimeout()
	reg.SetResetInProgress(false)

	var buf bytes.Buffer
	reg.WritePrometheus(&buf)
	out := buf.String()
	if err := checkPrometheusFamilies(out); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(out, "alice") || strings.Contains(out, "bob") {
		t.Fatalf("identity in metrics: %s", out)
	}
	for _, n := range []string{"token", "session=", "password", "uid=alice", "req-"} {
		if strings.Contains(strings.ToLower(out), n) && strings.Contains(out, "alice") {
			t.Fatalf("forbidden label %q: %s", n, out)
		}
	}
	for _, want := range []string{
		`labldap_http_requests_total{method="GET",route="/api/v1/users/{id}",status_class="2xx"} 1`,
		`labldap_http_requests_total{method="GET",route="/api/v1/users/{id}",status_class="4xx"} 1`,
		`labldap_mcp_requests_total{tool="ldap_search_entries",outcome="success"} 1`,
		`labldap_auth_total{result="success",reason="ok"} 1`,
		`labldap_auth_total{result="failure",reason="invalid"} 1`,
		`labldap_ldap_pool_max 16`,
		`labldap_build_info{version="dev",revision="abc123"} 1`,
		`labldap_reset_total{outcome="success"} 1`,
		`labldap_export_total{outcome="failure"} 1`,
	} {
		if !strings.Contains(out, want) {
			t.Fatalf("missing %s\n%s", want, out)
		}
	}
}

func TestWritePrometheusKeepsFamiliesContiguous(t *testing.T) {
	t.Parallel()
	reg := observability.NewRegistry(observability.BuildInfo{Version: "dev", Revision: "r1"})
	reg.ObserveHTTP("GET", "/health", "2xx", time.Millisecond)
	reg.ObserveHTTP("POST", "/api/v1/users", "2xx", time.Millisecond)
	var buf bytes.Buffer
	reg.WritePrometheus(&buf)
	if err := checkPrometheusFamilies(buf.String()); err != nil {
		t.Fatal(err)
	}
}

func TestMetricsSnapshotWithoutReadyProbe(t *testing.T) {
	t.Parallel()
	reg := observability.NewRegistry(observability.BuildInfo{Version: "dev", Revision: "r1"})
	reg.SetSnapshots(func() (int, int, int, int) { return 3, 4, 16, 1 }, func() bool { return true })
	var buf bytes.Buffer
	reg.WritePrometheus(&buf)
	out := buf.String()
	for _, want := range []string{
		"labldap_ldap_pool_active 3",
		"labldap_ldap_pool_idle 4",
		"labldap_ldap_pool_max 16",
		"labldap_ldap_pool_waiters 1",
		"labldap_reset_in_progress 1",
	} {
		if !strings.Contains(out, want) {
			t.Fatalf("missing %s\n%s", want, out)
		}
	}
}

func TestRouteTemplateDoesNotEchoIDs(t *testing.T) {
	t.Parallel()
	if got := observability.RouteTemplate("GET", "/api/v1/users/alice"); got != "/api/v1/users/{id}" {
		t.Fatal(got)
	}
	if got := observability.RouteTemplate("POST", "/api/v1/groups/staff/members"); got != "/api/v1/groups/{id}/members" {
		t.Fatal(got)
	}
	if got := observability.RouteTemplate("GET", "/totally/unknown/path"); got != "other" {
		t.Fatal(got)
	}
}

func checkPrometheusFamilies(text string) error {
	// Each metric name's samples must form one contiguous block after its
	// HELP/TYPE lines (Prometheus 0.0.4 exposition).
	seen := map[string]bool{}
	var current string
	for _, line := range strings.Split(text, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			if strings.HasPrefix(line, "# TYPE ") {
				fields := strings.Fields(line)
				if len(fields) >= 3 {
					current = fields[2]
				}
			}
			continue
		}
		name := line
		if i := strings.IndexByte(line, '{'); i > 0 {
			name = line[:i]
		} else if i := strings.IndexByte(line, ' '); i > 0 {
			name = line[:i]
		}
		if seen[name] && name != current {
			return fmt.Errorf("metric %s is not contiguous (interrupted by %s)", name, current)
		}
		seen[name] = true
		current = name
	}
	return nil
}
