package api

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/hilather/go-lab-ldap-mcp/api/generated"
	"github.com/hilather/go-lab-ldap-mcp/internal/audit"
	"github.com/hilather/go-lab-ldap-mcp/internal/auth"
	"github.com/hilather/go-lab-ldap-mcp/internal/observability"
)

func auditServer(t *testing.T) (*Server, *audit.Sink) {
	t.Helper()
	sink := audit.NewSink(nil, 32)
	reg, err := auth.NewRegistry([]auth.Token{
		{ID: "admin", Scopes: []string{auth.ScopeDirectoryRead, auth.ScopeDirectoryWrite, auth.ScopeAuditRead}, Secret: observability.Secret(testToken)},
		{ID: "auditor", Scopes: []string{auth.ScopeAuditRead}, Secret: observability.Secret(auditOnlyToken)},
		{ID: "reader", Scopes: []string{auth.ScopeDirectoryRead}, Secret: observability.Secret(readOnlyToken)},
	})
	if err != nil {
		t.Fatal(err)
	}
	s, err := New(Options{
		Registry:  reg,
		Sessions:  auth.NewStore(auth.DefaultSessionConfig()),
		Audit:     sink,
		AuditHook: sink,
		CursorKey: mustCursorKey(t),
	})
	if err != nil {
		t.Fatal(err)
	}
	return s, sink
}

func mustCursorKey(t *testing.T) []byte {
	t.Helper()
	return bytesRepeat(32, 0x11)
}

func bytesRepeat(n int, b byte) []byte {
	out := make([]byte, n)
	for i := range out {
		out[i] = b
	}
	return out
}

func TestAuditQueryRequiresScopeAndFilters(t *testing.T) {
	t.Parallel()
	s, sink := auditServer(t)
	h := s.Handler()
	sink.Emit(t.Context(), audit.Event{
		Time: time.Now().UTC(), Actor: "token:admin", Action: audit.ActionUserCreate,
		Target: "alice", Result: audit.ResultSuccess, RequestID: "r1",
	})
	sink.Emit(t.Context(), audit.Event{
		Time: time.Now().UTC(), Actor: "token:admin", Action: audit.ActionBindTest,
		Target: "bind", Result: "success", RequestID: "r2",
	})
	sink.Emit(t.Context(), audit.Event{
		Time: time.Now().UTC(), Actor: "session:abc", Action: audit.ActionUserCreate,
		Target: "bob", Result: audit.ResultSuccess, RequestID: "r3",
	})

	unauth := httptest.NewRequest(http.MethodGet, "/api/v1/audit", nil)
	ur := httptest.NewRecorder()
	h.ServeHTTP(ur, unauth)
	if ur.Code != http.StatusUnauthorized {
		t.Fatalf("unauth %d %s", ur.Code, ur.Body.String())
	}

	forbid := httptest.NewRequest(http.MethodGet, "/api/v1/audit", nil)
	forbid.Header.Set("Authorization", "Bearer "+readOnlyToken)
	fr := httptest.NewRecorder()
	h.ServeHTTP(fr, forbid)
	if fr.Code != http.StatusForbidden {
		t.Fatalf("reader %d %s", fr.Code, fr.Body.String())
	}

	ok := httptest.NewRequest(http.MethodGet, "/api/v1/audit?action=user.create&pageSize=10", nil)
	ok.Header.Set("Authorization", "Bearer "+auditOnlyToken)
	or := httptest.NewRecorder()
	h.ServeHTTP(or, ok)
	if or.Code != http.StatusOK {
		t.Fatalf("list %d %s", or.Code, or.Body.String())
	}
	if or.Header().Get("Cache-Control") != "no-store" {
		t.Fatal("cache")
	}
	var page generated.AuditPage
	decodeOpenAPI(t, or, &page)
	if len(page.Items) != 2 {
		t.Fatalf("items=%d body=%s", len(page.Items), or.Body.String())
	}
	for _, ev := range page.Items {
		if ev.Action != "user.create" {
			t.Fatalf("%+v", ev)
		}
		if strings.Contains(ev.Actor, testToken) || strings.Contains(ev.Actor, "Bearer") {
			t.Fatalf("secret actor %q", ev.Actor)
		}
	}
	assertNoSecret(t, or.Body.String(), testToken, auditOnlyToken, readOnlyToken)

	actor := httptest.NewRequest(http.MethodGet, "/api/v1/audit?actor=session:abc", nil)
	actor.Header.Set("Authorization", "Bearer "+auditOnlyToken)
	ar := httptest.NewRecorder()
	h.ServeHTTP(ar, actor)
	if ar.Code != http.StatusOK {
		t.Fatalf("actor %d %s", ar.Code, ar.Body.String())
	}
	var ap generated.AuditPage
	decodeOpenAPI(t, ar, &ap)
	if len(ap.Items) != 1 || ap.Items[0].Target != "bob" {
		t.Fatalf("%+v", ap.Items)
	}
}

func TestAuditCursorAndSessionEvents(t *testing.T) {
	t.Parallel()
	s, _ := auditServer(t)
	h := s.Handler()
	csrf, cookie := loginSession(t, h)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/audit?action=session.create&pageSize=1", nil)
	req.Header.Set("Authorization", "Bearer "+auditOnlyToken)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("list %d %s", rec.Code, rec.Body.String())
	}
	var page generated.AuditPage
	decodeOpenAPI(t, rec, &page)
	if len(page.Items) != 1 || page.Items[0].Action != "session.create" {
		t.Fatalf("%+v", page)
	}
	if page.Items[0].Actor != "token:admin" {
		t.Fatalf("actor %q", page.Items[0].Actor)
	}
	if _, err := time.Parse(time.RFC3339, page.Items[0].Time.UTC().Format(time.RFC3339)); err != nil {
		t.Fatalf("time %v", page.Items[0].Time)
	}
	assertNoSecret(t, rec.Body.String(), testToken, cookie, csrf)

	del := httptest.NewRequest(http.MethodDelete, "/api/v1/session", nil)
	del.Host = "127.0.0.1:8443"
	del.Header.Set("Origin", "http://127.0.0.1:8443")
	del.Header.Set(auth.CSRFHeader, csrf)
	del.AddCookie(auth.NewSessionCookie(cookie, false, 0))
	dr := httptest.NewRecorder()
	h.ServeHTTP(dr, del)
	if dr.Code != http.StatusNoContent {
		t.Fatalf("delete %d %s", dr.Code, dr.Body.String())
	}

	gone := httptest.NewRequest(http.MethodGet, "/api/v1/audit?action=session.destroy", nil)
	gone.Header.Set("Authorization", "Bearer "+auditOnlyToken)
	gr := httptest.NewRecorder()
	h.ServeHTTP(gr, gone)
	var destroyed generated.AuditPage
	decodeOpenAPI(t, gr, &destroyed)
	if len(destroyed.Items) != 1 || !strings.HasPrefix(destroyed.Items[0].Actor, "session:") {
		t.Fatalf("%+v", destroyed.Items)
	}
	if strings.Contains(gr.Body.String(), cookie) {
		t.Fatalf("cookie in audit: %s", gr.Body.String())
	}
}

func TestRequireScopeEmitsAuthzDeny(t *testing.T) {
	t.Parallel()
	s, sink := auditServer(t)
	req := httptest.NewRequest(http.MethodGet, "/api/v1/audit", nil)
	req.Header.Set("Authorization", "Bearer "+readOnlyToken)
	rec := httptest.NewRecorder()
	s.Handler().ServeHTTP(rec, req)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("%d %s", rec.Code, rec.Body.String())
	}
	page, err := sink.List(t.Context(), audit.ListQuery{Action: audit.ActionAuthzDeny, PageSize: 10})
	if err != nil {
		t.Fatal(err)
	}
	var saw bool
	for _, ev := range page.Items {
		if ev.Actor == "token:reader" && ev.Target == auth.ScopeAuditRead {
			saw = true
		}
	}
	if !saw {
		t.Fatalf("missing authz.deny: %+v", page.Items)
	}
}

func TestAuditPageJSONKeys(t *testing.T) {
	t.Parallel()
	s, sink := auditServer(t)
	sink.Emit(t.Context(), audit.Event{
		Time: time.Now().UTC(), Actor: "token:admin", Action: audit.ActionExport,
		Target: "export", Result: audit.ResultSuccess, RequestID: "rid",
	})
	req := httptest.NewRequest(http.MethodGet, "/api/v1/audit", nil)
	req.Header.Set("Authorization", "Bearer "+auditOnlyToken)
	rec := httptest.NewRecorder()
	s.Handler().ServeHTTP(rec, req)
	var raw map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &raw); err != nil {
		t.Fatal(err)
	}
	items, _ := raw["items"].([]any)
	if len(items) != 1 {
		t.Fatalf("%s", rec.Body.String())
	}
	ev := items[0].(map[string]any)
	for _, k := range []string{"time", "action", "actor", "target", "result", "requestId", "revisions"} {
		if _, ok := ev[k]; !ok {
			t.Fatalf("missing %s in %s", k, rec.Body.String())
		}
	}
}
