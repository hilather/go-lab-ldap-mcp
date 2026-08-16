//go:build integration

package dirsrv

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/hilather/go-lab-ldap-mcp/internal/app"
	"github.com/hilather/go-lab-ldap-mcp/internal/audit"
	"github.com/hilather/go-lab-ldap-mcp/internal/directory"
	"github.com/hilather/go-lab-ldap-mcp/internal/observability"
)

const appUserPass = "app-svc-pass-12"
const appTokenCanary = "app-mgmt-token-99"

func TestApplicationServicesOnEngine(t *testing.T) {
	env := startRuntimeEnv(t)
	sink := &audit.Memory{}
	svc := app.New(app.Deps{
		Users:  env.rt.Users(),
		Groups: env.rt.Groups(),
		Search: env.rt,
		Bind:   env.rt,
		Schema: env.rt,
		Caps:   env.rt,
		Marker: env.rt,
		Audit:  app.HookAuditor{Hook: sink},
	})
	p := app.Principal{Kind: app.KindToken, ID: "admin", Scopes: directory.ScopeSet{
		"directory:read", "directory:write", "directory:password", "schema:read",
	}}
	ctx := t.Context()

	u, err := svc.Users.Create(ctx, p, app.CreateUser{
		ID: "svc-alice", Password: observability.Secret(appUserPass),
		Attributes: map[string]string{"sn": "Service", "description": "orig"},
	})
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	assertNoPassword(t, u, appUserPass, appTokenCanary)

	runtimeReplace(t, env.dial, u.DN, "description", "direct-ldap")
	fresh, err := svc.Users.Get(ctx, p, "svc-alice")
	if err != nil {
		t.Fatal(err)
	}
	if attrValue(fresh, "description") != "direct-ldap" {
		t.Fatalf("direct mutation not visible: %+v", fresh.Attributes)
	}
	if fresh.Revision == u.Revision {
		t.Fatal("direct mutation must change revision")
	}

	g, err := svc.Groups.Create(ctx, p, directory.GroupSpec{
		ID: "svc-staff", Members: []directory.MemberRef{{Kind: "user", ID: "svc-alice"}},
	})
	if err != nil {
		t.Fatalf("group: %v", err)
	}
	if err := svc.Groups.Delete(ctx, p, "svc-staff", g.Revision); err != nil {
		t.Fatal(err)
	}

	page, err := svc.Query.Search(ctx, p, directory.SearchQuery{
		Base: "ou=people,dc=example,dc=test", Scope: directory.SearchScopeOne,
		Filter: "(uid=svc-alice)", Attributes: []string{"uid", "userPassword"},
	})
	if err != nil {
		t.Fatal(err)
	}
	raw, _ := json.Marshal(page)
	if strings.Contains(string(raw), appUserPass) || strings.Contains(strings.ToLower(string(raw)), "userpassword") {
		t.Fatalf("search leaked secret: %s", raw)
	}

	b, err := svc.Query.Baseline(ctx, p)
	if err != nil {
		t.Fatalf("baseline: %v", err)
	}
	if b.AppliedRevision == "" && b.ExpectedRevision != "" && b.ControlRevision != "" {
		t.Logf("marker unread: %+v", b)
	}

	for _, ev := range sink.Snapshot() {
		eraw, _ := json.Marshal(ev)
		if strings.Contains(string(eraw), appUserPass) || strings.Contains(string(eraw), appTokenCanary) {
			t.Fatalf("audit leaked secret: %s", eraw)
		}
	}
}
