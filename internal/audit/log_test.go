package audit

import (
	"bytes"
	"log/slog"
	"strings"
	"testing"

	"github.com/hilather/go-lab-ldap-mcp/internal/observability"
)

func TestLogSinkOmitsSecrets(t *testing.T) {
	t.Parallel()
	var buf bytes.Buffer
	log := slog.New(slog.NewJSONHandler(&buf, nil))
	s := NewSink(log, 8)
	s.Emit(t.Context(), Event{
		RequestID: "req-1",
		Actor:     "token:admin",
		Action:    ActionUserSetPassword,
		Target:    "alice",
		Result:    ResultSuccess,
	})
	out := buf.String()
	if !strings.Contains(out, `"audit.action":"user.set_password"`) {
		t.Fatalf("missing action: %s", out)
	}
	if !strings.Contains(out, `"audit.actor":"token:admin"`) {
		t.Fatalf("missing actor: %s", out)
	}
	for _, n := range []string{"password=", "Bearer ", "Authorization", "labldap_session="} {
		if strings.Contains(out, n) {
			t.Fatalf("secret-like %q in %s", n, out)
		}
	}
	page, err := s.List(t.Context(), ListQuery{PageSize: 10})
	if err != nil {
		t.Fatal(err)
	}
	if len(page.Items) != 1 || page.Items[0].Actor != "token:admin" {
		t.Fatalf("%+v", page.Items)
	}
	_ = observability.Secret("must-not-appear-in-this-test")
}
