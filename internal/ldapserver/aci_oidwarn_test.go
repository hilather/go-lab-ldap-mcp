package ldapserver

import (
	"bytes"
	"log/slog"
	"strings"
	"testing"
)

// TestNumericTargetAttrWarnsAtStartup pins the CAND-32 mitigation: each
// numeric-OID targetattr name logs one startup warning (it is compared
// literally, so it never covers the attribute's name); plain names do not.
func TestNumericTargetAttrWarnsAtStartup(t *testing.T) {
	t.Parallel()
	const tail = `(version 3.0; acl "labldap:%s"; allow (read) userdn="ldap:///uid=a,ou=people,dc=example,dc=test";)`
	aci := func(id, ta string) string {
		return `(target="ldap:///dc=example,dc=test")(targetattr` + ta + `)` + strings.Replace(tail, "%s", id, 1)
	}
	var buf bytes.Buffer
	logger := slog.New(slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: slog.LevelWarn}))
	if _, err := NewACIEngine([]string{
		aci("oid-list", `="2.5.4.4 || uid || 2.5.4.35"`),
		aci("oid-deny", `!="0.9.2342.19200300.100.1.1"`),
		aci("names", `="uid || sn"`),
		aci("star", `="*"`),
	}, logger); err != nil {
		t.Fatal(err)
	}
	out := buf.String()
	if n := strings.Count(out, "numeric OID"); n != 3 {
		t.Fatalf("want 3 numeric-OID warnings, got %d:\n%s", n, out)
	}
	for _, want := range []string{"targetattr=2.5.4.4", "targetattr=2.5.4.35", "targetattr=0.9.2342.19200300.100.1.1"} {
		if !strings.Contains(out, want) {
			t.Errorf("missing %q in:\n%s", want, out)
		}
	}
	if strings.Contains(out, "labldap:names") || strings.Contains(out, "labldap:star") {
		t.Errorf("plain names must not warn:\n%s", out)
	}
}
