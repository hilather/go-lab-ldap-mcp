//go:build integration

package dirsrv

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/hilather/go-lab-ldap-mcp/internal/api"
	"github.com/hilather/go-lab-ldap-mcp/internal/app"
	"github.com/hilather/go-lab-ldap-mcp/internal/auth"
	"github.com/hilather/go-lab-ldap-mcp/internal/config"
	"github.com/hilather/go-lab-ldap-mcp/internal/directory"
	"github.com/hilather/go-lab-ldap-mcp/internal/observability"
	"github.com/hilather/go-lab-ldap-mcp/internal/reset"
)

const (
	crossAdminToken = "lab-it-cross-admin-token-32xxxx"
	crossWriteToken = "lab-it-cross-write-token-32xxxx"
	crossAppPass    = "cross-app-user-pass-12"
	crossRESTPass   = "cross-rest-user-pass-12"
	crossSeedPass   = "seed-alice-pass-12"
)

func TestCrossInterfaceResetAndExport(t *testing.T) {
	env := startRuntimeEnv(t)
	before, err := env.rt.ReadMarker(t.Context())
	if err != nil || strings.TrimSpace(before.AppliedRevision) == "" {
		t.Fatalf("marker %+v %v", before, err)
	}
	sec := config.ResolvedSecret{Path: "alice.pw", Value: observability.Secret(crossSeedPass)}
	gate := reset.NewGate()
	logs := &bytes.Buffer{}
	svc := app.New(app.Deps{
		Users:            env.rt.Users(),
		Groups:           env.rt.Groups(),
		Bind:             env.rt,
		Marker:           env.rt,
		ResetDir:         env.rt,
		Gate:             gate,
		ResetLock:        gate,
		SoftReset:        true,
		ScenarioName:     "lab",
		ExpectedRevision: before.AppliedRevision,
		PeopleDN:         "ou=people,dc=example,dc=test",
		GroupsDN:         "ou=groups,dc=example,dc=test",
		Suffix:           "dc=example,dc=test",
		RuntimeDN:        "uid=rt,ou=people,dc=example,dc=test",
		MarkerDN:         "cn=labldap-baseline,dc=example,dc=test",
		Secrets:          config.MapResolver{"alice.pw": crossSeedPass},
		ResetUsers: []config.NormalizedUser{{
			ID: "alice", UID: "alice", DN: "uid=alice,ou=people,dc=example,dc=test",
			Enabled: true, Password: &sec,
			Attributes: []config.AttrKV{{Name: "sn", Value: "Seed"}},
		}},
		ResetGroups: []config.NormalizedGroup{{
			ID: "staff", DN: "cn=staff,ou=groups,dc=example,dc=test",
			Members: []config.MemberRef{{Kind: "user", ID: "alice", DN: "uid=alice,ou=people,dc=example,dc=test"}},
		}},
		BindTransport:    directory.TransportLDAPS,
		ExportMaxEntries: 20000,
		ExportMaxBytes:   1 << 20,
	})
	reg, err := auth.NewRegistry([]auth.Token{
		{ID: "admin", Scopes: []string{
			auth.ScopeDirectoryRead, auth.ScopeDirectoryWrite, auth.ScopeDirectoryPassword,
			auth.ScopeLabReset, auth.ScopeLabExport,
		}, Secret: observability.Secret(crossAdminToken)},
		{ID: "writer", Scopes: []string{auth.ScopeDirectoryWrite}, Secret: observability.Secret(crossWriteToken)},
	})
	if err != nil {
		t.Fatal(err)
	}
	srv, err := api.New(api.Options{
		Registry: reg,
		Sessions: auth.NewStore(auth.DefaultSessionConfig()),
		Users:    svc.Users,
		Groups:   svc.Groups,
		Reset:    svc.Reset,
		Export:   svc.Export,
		Logger:   observability.NewLogger(logs, observability.FormatJSON, observability.CurrentBuild("labldap")),
	})
	if err != nil {
		t.Fatal(err)
	}
	h := srv.Handler()
	admin := app.Principal{Kind: app.KindToken, ID: "admin", Scopes: directory.ScopeSet{
		"directory:read", "directory:write", "directory:password", "lab:reset", "lab:export",
	}}

	if _, err := svc.Users.Create(t.Context(), admin, app.CreateUser{
		ID: "app-bob", Password: observability.Secret(crossAppPass),
		Attributes: map[string]string{"sn": "App"},
	}); err != nil {
		t.Fatalf("app create: %v", err)
	}

	create := httptest.NewRequest(http.MethodPost, "/api/v1/users", strings.NewReader(`{"id":"rest-carol","password":"`+crossRESTPass+`","attributes":{"sn":"REST"}}`))
	create.Header.Set("Authorization", "Bearer "+crossAdminToken)
	create.Header.Set("Content-Type", "application/json")
	cr := httptest.NewRecorder()
	h.ServeHTTP(cr, create)
	if cr.Code != http.StatusCreated {
		t.Fatalf("rest create %d %s", cr.Code, cr.Body.String())
	}

	addExtraPerson(t, env.inst, "uid=runtime-extra,ou=people,dc=example,dc=test")

	var beforeExport bytes.Buffer
	if err := svc.Export.Write(t.Context(), admin, &beforeExport, app.ExportRequest{}); err != nil {
		t.Fatal(err)
	}
	beforeLDIF := beforeExport.String()
	assertNoSeedSecrets(t, beforeLDIF, logs.String())
	for _, dn := range []string{"uid=app-bob,", "uid=rest-carol,", "uid=runtime-extra,"} {
		if !strings.Contains(strings.ToLower(beforeLDIF), dn) {
			t.Fatalf("export missing %s:\n%s", dn, beforeLDIF)
		}
	}

	deny := httptest.NewRequest(http.MethodPost, "/api/v1/reset", strings.NewReader(`{"name":"lab","expectedRevision":"`+before.AppliedRevision+`"}`))
	deny.Header.Set("Authorization", "Bearer "+crossWriteToken)
	deny.Header.Set("Content-Type", "application/json")
	dr := httptest.NewRecorder()
	h.ServeHTTP(dr, deny)
	if dr.Code != http.StatusForbidden {
		t.Fatalf("write reset %d %s", dr.Code, dr.Body.String())
	}

	wrong := httptest.NewRequest(http.MethodPost, "/api/v1/reset", strings.NewReader(`{"name":"nope","expectedRevision":"`+before.AppliedRevision+`"}`))
	wrong.Header.Set("Authorization", "Bearer "+crossAdminToken)
	wrong.Header.Set("Content-Type", "application/json")
	wr := httptest.NewRecorder()
	h.ServeHTTP(wr, wrong)
	if wr.Code != http.StatusConflict {
		t.Fatalf("wrong name %d %s", wr.Code, wr.Body.String())
	}

	resetBody := `{"name":"lab","expectedRevision":"` + before.AppliedRevision + `"}`
	doReset := func() {
		t.Helper()
		req := httptest.NewRequest(http.MethodPost, "/api/v1/reset", strings.NewReader(resetBody))
		req.Header.Set("Authorization", "Bearer "+crossAdminToken)
		req.Header.Set("Content-Type", "application/json")
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		if rec.Code != http.StatusAccepted {
			t.Fatalf("reset %d %s", rec.Code, rec.Body.String())
		}
		var st app.ResetStatus
		if err := json.Unmarshal(rec.Body.Bytes(), &st); err != nil {
			t.Fatal(err)
		}
		if st.State != string(reset.Ready) || st.ExpectedRevision != before.AppliedRevision {
			t.Fatalf("status %+v", st)
		}
	}
	doReset()
	assertBaselineRestored(t, env, svc, admin, before.AppliedRevision)
	doReset()
	assertBaselineRestored(t, env, svc, admin, before.AppliedRevision)

	exp := httptest.NewRequest(http.MethodGet, "/api/v1/export", nil)
	exp.Header.Set("Authorization", "Bearer "+crossAdminToken)
	er := httptest.NewRecorder()
	h.ServeHTTP(er, exp)
	if er.Code != http.StatusOK {
		t.Fatalf("export %d %s", er.Code, er.Body.String())
	}
	after := er.Body.String()
	assertNoSeedSecrets(t, after, logs.String(), er.Body.String())
	if strings.Contains(strings.ToLower(after), "uid=runtime-extra,") ||
		strings.Contains(strings.ToLower(after), "uid=app-bob,") ||
		strings.Contains(strings.ToLower(after), "uid=rest-carol,") {
		t.Fatalf("extras remained in export:\n%s", after)
	}
	if !strings.Contains(strings.ToLower(after), "uid=alice,") {
		t.Fatalf("alice missing after reset:\n%s", after)
	}
	if !strings.Contains(after, directory.LDIFCompleteMark) {
		t.Fatalf("incomplete export:\n%s", after)
	}
	parsed, err := directory.ParseLDIF(strings.NewReader(after))
	if err != nil || len(parsed) == 0 {
		t.Fatalf("parse export %d %v", len(parsed), err)
	}

	get := httptest.NewRequest(http.MethodGet, "/api/v1/reset", nil)
	get.Header.Set("Authorization", "Bearer "+crossAdminToken)
	gr := httptest.NewRecorder()
	h.ServeHTTP(gr, get)
	if gr.Code != http.StatusOK || !strings.Contains(gr.Body.String(), `"state":"Ready"`) {
		t.Fatalf("get reset %d %s", gr.Code, gr.Body.String())
	}
}

func assertBaselineRestored(t *testing.T, env *runtimeEnv, svc *app.Services, p app.Principal, rev string) {
	t.Helper()
	if _, err := svc.Users.Get(t.Context(), p, "alice"); err != nil {
		t.Fatalf("alice missing: %v", err)
	}
	if _, err := svc.Users.Get(t.Context(), p, "app-bob"); err == nil {
		t.Fatal("app-bob remained")
	}
	if _, err := svc.Users.Get(t.Context(), p, "rest-carol"); err == nil {
		t.Fatal("rest-carol remained")
	}
	extra := ldapSearchAllowMissing(t, env.inst, "uid=runtime-extra,ou=people,dc=example,dc=test")
	if strings.Contains(extra, "uid=runtime-extra,ou=people,dc=example,dc=test") {
		t.Fatalf("ldap extra remained:\n%s", extra)
	}
	if err := userBind(t, env.inst, "uid=alice,ou=people,dc=example,dc=test", crossSeedPass); err != nil {
		t.Fatalf("alice bind: %v", err)
	}
	after, err := env.rt.ReadMarker(t.Context())
	if err != nil || after.AppliedRevision != rev {
		t.Fatalf("marker changed %q -> %+v %v", rev, after, err)
	}
}

func assertNoSeedSecrets(t *testing.T, parts ...string) {
	t.Helper()
	joined := strings.Join(parts, "\n")
	for _, secret := range []string{crossAppPass, crossRESTPass, crossSeedPass, "runtime-secret", crossAdminToken, crossWriteToken} {
		if strings.Contains(joined, secret) {
			t.Fatalf("secret %q leaked", secret)
		}
	}
	if strings.Contains(strings.ToLower(joined), "userpassword:") || strings.Contains(strings.ToLower(joined), "userpassword::") {
		t.Fatalf("userPassword in export/logs")
	}
}
