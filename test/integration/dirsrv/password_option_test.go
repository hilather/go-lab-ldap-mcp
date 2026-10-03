//go:build integration

package dirsrv

import (
	"crypto/tls"
	"crypto/x509"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
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

// Must not start with "{" or the native engine treats it as pre-hashed (D3).
const optionPasswordCanary = "pwopt-regression-canary-5c1d"

// TestPasswordOptionSpellingsAreRejectedAndRedacted is the both-engine
// regression for attribute-option and OID spellings of protected attributes:
// the control plane rejects them on write, never returns them on read, and
// the engines differ only in how a direct DM write is stored (Delta D31).
func TestPasswordOptionSpellingsAreRejectedAndRedacted(t *testing.T) {
	env := startCompatEngineFromYAML(t, workflowYAML())
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
	reg, err := auth.NewRegistry([]auth.Token{{ID: "admin", Scopes: []string{auth.ScopeDirectoryRead, auth.ScopeDirectoryWrite, auth.ScopeDirectoryPassword}, Secret: observability.Secret(wfAdminToken)}})
	if err != nil {
		t.Fatal(err)
	}
	srv, err := api.New(api.Options{Registry: reg, Sessions: auth.NewStore(auth.DefaultSessionConfig()), Users: svc.Users, Groups: svc.Groups, Query: svc.Query, Entries: svc.Entries})
	if err != nil {
		t.Fatal(err)
	}
	h := srv.Handler()
	do := func(method, path, ifMatch, body string) (int, string, string) {
		t.Helper()
		req := httptest.NewRequest(method, path, strings.NewReader(body))
		req.Header.Set("Authorization", "Bearer "+wfAdminToken)
		if body != "" {
			req.Header.Set("Content-Type", "application/json")
		}
		if ifMatch != "" {
			req.Header.Set("If-Match", ifMatch)
		}
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		return rec.Code, rec.Body.String(), rec.Header().Get("ETag")
	}

	if code, body, _ := do(http.MethodPost, "/api/v1/users", "", `{"id":"pwopt","password":"Normal-Pass-1234!","attributes":{"sn":"Option"}}`); code != http.StatusCreated {
		t.Fatalf("create user: %d %s", code, body)
	}
	dn := "uid=pwopt,ou=people,dc=example,dc=test"
	q := "/api/v1/entries?dn=" + url.QueryEscape(dn)

	// (a) PATCH with option/OID spellings of protected names is rejected.
	for _, name := range []string{"userPassword;lang-en", "USERPASSWORD;x-a", "2.5.4.35", "aci;lang-en", "nsAccountLock;x-a"} {
		_, _, et := do(http.MethodGet, q, "", "")
		code, body, _ := do(http.MethodPatch, q, et, `{"changes":[{"op":"add","name":"`+name+`","values":["`+optionPasswordCanary+`"]}]}`)
		if code != http.StatusBadRequest || !strings.Contains(body, "forbidden_attribute") {
			t.Fatalf("PATCH %s: %d %s", name, code, strings.ReplaceAll(body, optionPasswordCanary, "<canary>"))
		}
	}
	// (b) Entry create with an optioned password attribute is rejected.
	code, body, _ := do(http.MethodPost, "/api/v1/entries", "", `{"dn":"uid=pwopt2,ou=people,dc=example,dc=test","objectClasses":["inetOrgPerson"],"attributes":{"sn":"Two","userPassword;lang-en":"`+optionPasswordCanary+`"}}`)
	if code != http.StatusBadRequest || !strings.Contains(body, "forbidden_attribute") {
		t.Fatalf("POST entry with optioned password: %d %s", code, strings.ReplaceAll(body, optionPasswordCanary, "<canary>"))
	}

	// (c) A direct DM write bypasses the control plane; reads still redact.
	lc := dialDM(t, env)
	mod := ldap.NewModifyRequest(dn, nil)
	mod.Add("userPassword;lang-en", []string{optionPasswordCanary})
	if err := lc.Modify(mod); err != nil {
		t.Fatalf("DM modify: %v", err)
	}
	code, body, _ = do(http.MethodGet, q, "", "")
	if code != http.StatusOK {
		t.Fatalf("GET entry: %d", code)
	}
	if strings.Contains(body, optionPasswordCanary) || strings.Contains(strings.ToLower(body), "userpassword") {
		t.Fatalf("entry read returned a userPassword spelling: %s", strings.ReplaceAll(body, optionPasswordCanary, "<canary>"))
	}
	code, body, _ = do(http.MethodPost, "/api/v1/search", "", `{"base":"`+dn+`","scope":"base","filter":"(uid=pwopt)","pageSize":10}`)
	if code != http.StatusOK || strings.Contains(body, optionPasswordCanary) {
		t.Fatalf("search: status %d, canary present %v", code, strings.Contains(body, optionPasswordCanary))
	}

	// (d) Storage differs by engine: native hashes, 389 keeps the value
	// as written (Delta D31; this assertion is the controlling test).
	res, err := lc.Search(ldap.NewSearchRequest(dn, ldap.ScopeBaseObject, ldap.NeverDerefAliases, 0, 0, false, "(objectClass=*)", []string{"userPassword;lang-en"}, nil))
	if err != nil || len(res.Entries) != 1 {
		t.Fatalf("DM read: %v", err)
	}
	var stored []string
	for _, a := range res.Entries[0].Attributes {
		if strings.HasPrefix(strings.ToLower(a.Name), "userpassword;") {
			stored = append(stored, a.Values...)
		}
	}
	if len(stored) != 1 {
		t.Fatalf("DM read optioned values = %d, want 1", len(stored))
	}
	switch env.engine {
	case EngineNative:
		if stored[0] == optionPasswordCanary || !strings.HasPrefix(stored[0], "{") {
			t.Fatal("native stored the optioned userPassword in plaintext")
		}
	default:
		if stored[0] != optionPasswordCanary {
			t.Fatal("389 optioned userPassword storage changed; update Delta D31")
		}
	}
}

func dialDM(t *testing.T, env compatEnv) *ldap.Conn {
	t.Helper()
	pem, err := os.ReadFile(env.caFile)
	if err != nil {
		t.Fatal(err)
	}
	roots := x509.NewCertPool()
	roots.AppendCertsFromPEM(pem)
	lc, err := ldap.DialURL("ldaps://"+env.ldapsAddr, ldap.DialWithTLSConfig(&tls.Config{RootCAs: roots, ServerName: env.serverName, MinVersion: tls.VersionTLS12}))
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	t.Cleanup(func() { _ = lc.Close() })
	if err := lc.Bind("cn=Directory Manager", env.dmPassword); err != nil {
		t.Fatalf("DM bind: %v", err)
	}
	return lc
}
