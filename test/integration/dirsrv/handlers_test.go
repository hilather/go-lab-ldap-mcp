//go:build integration

package dirsrv

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/hilather/go-lab-ldap-mcp/internal/api"
	"github.com/hilather/go-lab-ldap-mcp/internal/app"
	"github.com/hilather/go-lab-ldap-mcp/internal/auth"
	"github.com/hilather/go-lab-ldap-mcp/internal/directory"
	"github.com/hilather/go-lab-ldap-mcp/internal/observability"
)

const (
	handlerUserPass    = "handler-user-pass-12"
	handlerUserPassNew = "handler-user-pass-99"
	handlerAdminToken  = "lab-it-admin-token-value-32xx"
	handlerWriteToken  = "lab-it-write-token-value-32xxx"
)

func TestRESTHandlersOnEngine(t *testing.T) {
	env := startRuntimeEnv(t)
	svc := app.New(app.Deps{
		Users:    env.rt.Users(),
		Groups:   env.rt.Groups(),
		Search:   env.rt,
		Bind:     env.rt,
		Schema:   env.rt,
		Caps:     env.rt,
		Marker:   env.rt,
		PeopleDN: "ou=people,dc=example,dc=test",
		GroupsDN: "ou=groups,dc=example,dc=test",
	})
	reg, err := auth.NewRegistry([]auth.Token{
		{ID: "admin", Scopes: []string{auth.ScopeDirectoryRead, auth.ScopeDirectoryWrite, auth.ScopeDirectoryPassword}, Secret: observability.Secret(handlerAdminToken)},
		{ID: "writer", Scopes: []string{auth.ScopeDirectoryWrite}, Secret: observability.Secret(handlerWriteToken)},
	})
	if err != nil {
		t.Fatal(err)
	}
	srv, err := api.New(api.Options{
		Registry: reg,
		Sessions: auth.NewStore(auth.DefaultSessionConfig()),
		Users:    svc.Users,
		Groups:   svc.Groups,
	})
	if err != nil {
		t.Fatal(err)
	}
	h := srv.Handler()

	create := httptest.NewRequest(http.MethodPost, "/api/v1/users", strings.NewReader(`{"id":"h-alice","password":"`+handlerUserPass+`","attributes":{"sn":"Handler"}}`))
	create.Header.Set("Authorization", "Bearer "+handlerAdminToken)
	create.Header.Set("Content-Type", "application/json")
	cr := httptest.NewRecorder()
	h.ServeHTTP(cr, create)
	if cr.Code != http.StatusCreated {
		t.Fatalf("create user %d %s", cr.Code, cr.Body.String())
	}
	if cr.Header().Get("Location") != "/api/v1/users/h-alice" || cr.Header().Get("ETag") == "" {
		t.Fatalf("create headers location=%q etag=%q", cr.Header().Get("Location"), cr.Header().Get("ETag"))
	}
	if strings.Contains(cr.Body.String(), handlerUserPass) {
		t.Fatalf("password in create response: %s", cr.Body.String())
	}
	var created struct {
		ID       string `json:"id"`
		DN       string `json:"dn"`
		Revision string `json:"revision"`
	}
	if err := json.Unmarshal(cr.Body.Bytes(), &created); err != nil {
		t.Fatal(err)
	}

	deny := httptest.NewRequest(http.MethodPost, "/api/v1/users/h-alice/password", strings.NewReader(`{"password":"`+handlerUserPassNew+`","revision":"`+created.Revision+`"}`))
	deny.Header.Set("Authorization", "Bearer "+handlerWriteToken)
	deny.Header.Set("Content-Type", "application/json")
	dr := httptest.NewRecorder()
	h.ServeHTTP(dr, deny)
	if dr.Code != http.StatusForbidden {
		t.Fatalf("write-only password %d %s", dr.Code, dr.Body.String())
	}

	setPW := httptest.NewRequest(http.MethodPost, "/api/v1/users/h-alice/password", strings.NewReader(`{"password":"`+handlerUserPassNew+`","revision":"`+created.Revision+`"}`))
	setPW.Header.Set("Authorization", "Bearer "+handlerAdminToken)
	setPW.Header.Set("Content-Type", "application/json")
	pr := httptest.NewRecorder()
	h.ServeHTTP(pr, setPW)
	if pr.Code != http.StatusNoContent {
		t.Fatalf("set password %d %s", pr.Code, pr.Body.String())
	}
	if pr.Body.Len() != 0 || strings.Contains(pr.Body.String(), handlerUserPassNew) {
		t.Fatalf("password response leaked: %q", pr.Body.String())
	}
	if err := userBind(t, env.inst, created.DN, handlerUserPassNew); err != nil {
		t.Fatalf("bind with new password: %v", err)
	}

	empty := httptest.NewRequest(http.MethodPost, "/api/v1/groups", strings.NewReader(`{"id":"h-empty","members":[]}`))
	empty.Header.Set("Authorization", "Bearer "+handlerAdminToken)
	empty.Header.Set("Content-Type", "application/json")
	er := httptest.NewRecorder()
	h.ServeHTTP(er, empty)
	if er.Code != http.StatusBadRequest || !strings.Contains(er.Body.String(), "empty_group") {
		t.Fatalf("empty group %d %s", er.Code, er.Body.String())
	}

	gcreate := httptest.NewRequest(http.MethodPost, "/api/v1/groups", strings.NewReader(`{"id":"h-staff","members":[{"kind":"user","id":"h-alice"}]}`))
	gcreate.Header.Set("Authorization", "Bearer "+handlerAdminToken)
	gcreate.Header.Set("Content-Type", "application/json")
	gcr := httptest.NewRecorder()
	h.ServeHTTP(gcr, gcreate)
	if gcr.Code != http.StatusCreated {
		t.Fatalf("create group %d %s", gcr.Code, gcr.Body.String())
	}
	var group struct {
		Revision string `json:"revision"`
	}
	if err := json.Unmarshal(gcr.Body.Bytes(), &group); err != nil {
		t.Fatal(err)
	}
	etag := gcr.Header().Get("ETag")

	addAgain := httptest.NewRequest(http.MethodPost, "/api/v1/groups/h-staff/members", strings.NewReader(`{"members":[{"kind":"user","id":"h-alice"}]}`))
	addAgain.Header.Set("Authorization", "Bearer "+handlerAdminToken)
	addAgain.Header.Set("Content-Type", "application/json")
	addAgain.Header.Set("If-Match", etag)
	ar := httptest.NewRecorder()
	h.ServeHTTP(ar, addAgain)
	if ar.Code != http.StatusOK {
		t.Fatalf("idempotent add %d %s", ar.Code, ar.Body.String())
	}
	var sum directory.MembershipSummary
	if err := json.Unmarshal(ar.Body.Bytes(), &sum); err != nil {
		t.Fatal(err)
	}
	if len(sum.Added) != 0 || len(sum.Unchanged) != 1 {
		t.Fatalf("idempotent add counts %+v", sum)
	}
}
