//go:build integration

package dirsrv

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/go-ldap/ldap/v3"

	"github.com/hilather/go-lab-ldap-mcp/internal/api"
	"github.com/hilather/go-lab-ldap-mcp/internal/app"
	"github.com/hilather/go-lab-ldap-mcp/internal/auth"
	"github.com/hilather/go-lab-ldap-mcp/internal/directory"
	"github.com/hilather/go-lab-ldap-mcp/internal/directory/ds389"
	"github.com/hilather/go-lab-ldap-mcp/internal/directory/ldapclient"
	"github.com/hilather/go-lab-ldap-mcp/internal/observability"
)

// TestFilterAttributeDescriptionsAreEngineNeutral (contract C6): filter
// spellings the control plane forwards (second descriptors, numeric OIDs of
// non-protected types, base names over subtype values) return the same
// entries on both engines; protected-type filters stay forbidden_attribute.
func TestFilterAttributeDescriptionsAreEngineNeutral(t *testing.T) {
	env := startCompatEngineFromYAML(t, workflowYAML())
	const alice = "uid=alice,ou=people,dc=example,dc=test"
	dm := dialDM(t, env)
	mod := ldap.NewModifyRequest(alice, nil)
	mod.Add("uid;x-test", []string{"alicetag"})
	if err := dm.Modify(mod); err != nil {
		t.Fatalf("DM add uid;x-test: %v", err)
	}

	cfg := ldapclient.Config{
		Address: env.ldapsAddr, Transport: directory.TransportLDAPS, CAFile: env.caFile,
		ServerName: env.serverName, BindDN: "uid=rt,ou=people,dc=example,dc=test",
		BindPassword: observability.Secret("runtime-secret"), DialTimeout: 8 * time.Second, PoolSize: 4,
	}
	pool, err := ldapclient.NewPool(cfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = pool.Close() })
	rt, err := ds389.NewRuntime(pool, ds389.RuntimeConfig{
		Suffix: "dc=example,dc=test", PeopleDN: "ou=people,dc=example,dc=test", GroupsDN: "ou=groups,dc=example,dc=test",
		RuntimeDN: "uid=rt,ou=people,dc=example,dc=test", Client: cfg, SchemaTTL: time.Minute,
	})
	if err != nil {
		t.Fatal(err)
	}
	svc := app.New(app.Deps{Users: rt.Users(), Groups: rt.Groups(), Entries: rt, Search: rt, Bind: rt, Schema: rt, Caps: rt, Marker: rt,
		PeopleDN: "ou=people,dc=example,dc=test", GroupsDN: "ou=groups,dc=example,dc=test", BindTransport: directory.TransportLDAPS})
	reg, err := auth.NewRegistry([]auth.Token{{ID: "admin", Scopes: []string{auth.ScopeDirectoryRead}, Secret: observability.Secret(wfAdminToken)}})
	if err != nil {
		t.Fatal(err)
	}
	srv, err := api.New(api.Options{Registry: reg, Sessions: auth.NewStore(auth.DefaultSessionConfig()), Users: svc.Users, Groups: svc.Groups, Query: svc.Query, Entries: svc.Entries})
	if err != nil {
		t.Fatal(err)
	}
	h := srv.Handler()
	search := func(filter string) (int, string) {
		t.Helper()
		body, _ := json.Marshal(map[string]any{"base": "ou=people,dc=example,dc=test", "filter": filter, "attributes": []string{"uid"}})
		req := httptest.NewRequest(http.MethodPost, "/api/v1/search", strings.NewReader(string(body)))
		req.Header.Set("Authorization", "Bearer "+wfAdminToken)
		req.Header.Set("Content-Type", "application/json")
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		return rec.Code, rec.Body.String()
	}
	hasAlice := func(body string) bool { return strings.Contains(strings.ToLower(body), alice) }

	for filter, want := range map[string]bool{
		"(userid=alice)":             true,
		"(!(userid=alice))":          false,
		"(2.5.4.0=inetOrgPerson)":    true,
		"(!(2.5.4.0=inetOrgPerson))": false,
		"(uid=alicetag)":             true,
		"(uid;x-test=alicetag)":      true,
		"(!(uid;x-test=alicetag))":   false,
		"(uid;x-other=alicetag)":     false,
	} {
		code, body := search(filter)
		if code != http.StatusOK {
			t.Fatalf("%s %s: %d %s", env.engine, filter, code, body)
		}
		if hasAlice(body) != want {
			t.Errorf("%s %s: alice returned=%v, want %v (%s)", env.engine, filter, !want, want, body)
		}
	}
	for _, filter := range []string{"(0.9.2342.19200300.100.1.1=alice)", "(userPassword=*)", "(userPassword;x-b=*)"} {
		code, body := search(filter)
		if code != http.StatusBadRequest || !strings.Contains(body, "forbidden_attribute") {
			t.Errorf("%s %s: %d %s, want 400 forbidden_attribute", env.engine, filter, code, body)
		}
	}

	// Direct DM: the uid OID resolves on both engines.
	res, err := dm.Search(ldap.NewSearchRequest("ou=people,dc=example,dc=test", ldap.ScopeSingleLevel, ldap.NeverDerefAliases, 0, 0, false,
		"(!(0.9.2342.19200300.100.1.1=alice))", []string{"1.1"}, nil))
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range res.Entries {
		if strings.EqualFold(e.DN, alice) {
			t.Fatalf("%s DM (!(uid-OID=alice)) returned alice", env.engine)
		}
	}
	if len(res.Entries) == 0 {
		t.Fatalf("%s DM (!(uid-OID=alice)) returned nothing (rt should match)", env.engine)
	}
}
