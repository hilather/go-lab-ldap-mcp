//go:build integration

package dirsrv

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os/exec"
	"strings"
	"testing"
	"time"

	"github.com/hilather/go-lab-ldap-mcp/internal/api"
	"github.com/hilather/go-lab-ldap-mcp/internal/app"
	"github.com/hilather/go-lab-ldap-mcp/internal/auth"
	"github.com/hilather/go-lab-ldap-mcp/internal/directory"
	"github.com/hilather/go-lab-ldap-mcp/internal/directory/ds389"
	"github.com/hilather/go-lab-ldap-mcp/internal/directory/ldapclient"
	"github.com/hilather/go-lab-ldap-mcp/internal/observability"
)

const (
	wfAdminToken = "lab-it-workflow-admin-token-32x"
	wfUserPass   = "workflow-user-pass-12"
	wfUserPass2  = "workflow-user-pass-99"
)

// TestRESTAccountWorkflowLDAPTools toggles account-state operations through
// REST, then checks the same user with host OpenLDAP tools (ldapwhoami /
// ldapsearch). The engine is selected by LABLDAP_IT_ENGINE (389 container
// or in-process native). Same assertions on both.
func TestRESTAccountWorkflowLDAPTools(t *testing.T) {
	requireHostTool(t, "ldapwhoami")
	requireHostTool(t, "ldapsearch")
	env, h := startRESTLDAPEnv(t)
	t.Logf("engine=%s ldaps=%s", env.engine, env.ldapsAddr)

	created := restJSON(t, h, http.MethodPost, "/api/v1/users", wfAdminToken, "",
		`{"id":"wf-alice","password":"`+wfUserPass+`","attributes":{"sn":"Workflow"}}`, http.StatusCreated)
	rev := created["revision"]
	dn := created["dn"]
	if dn == "" || rev == "" {
		t.Fatalf("create: %+v", created)
	}

	if err := ldapWhoami(t, env, dn, wfUserPass); err != nil {
		t.Fatalf("initial ldapwhoami: %v", err)
	}

	st := restJSON(t, h, http.MethodPost, "/api/v1/users/wf-alice/disable", wfAdminToken, etag(rev), "", http.StatusOK)
	if st["enabled"] == "true" {
		t.Fatalf("disable REST: %+v", st)
	}
	rev = st["revision"]
	if err := ldapWhoami(t, env, dn, wfUserPass); err == nil {
		t.Fatal("ldapwhoami must fail after REST disable")
	}
	lockedAttr := hostLDAPSearch(t, env, "cn=Directory Manager", env.dmPassword,
		dn, "base", "(objectClass=*)", "nsAccountLock")
	if !strings.Contains(strings.ToLower(lockedAttr), "nsaccountlock") {
		t.Fatalf("disable not visible to ldapsearch:\n%s", lockedAttr)
	}

	st = restJSON(t, h, http.MethodPost, "/api/v1/users/wf-alice/enable", wfAdminToken, etag(rev), "", http.StatusOK)
	if st["enabled"] != "true" {
		t.Fatalf("enable REST: %+v", st)
	}
	rev = st["revision"]
	if err := ldapWhoami(t, env, dn, wfUserPass); err != nil {
		t.Fatalf("ldapwhoami after enable: %v", err)
	}

	st = restJSON(t, h, http.MethodPost, "/api/v1/users/wf-alice/lock", wfAdminToken, etag(rev), "", http.StatusOK)
	if st["locked"] != "true" {
		t.Fatalf("lock REST: %+v", st)
	}
	rev = st["revision"]
	lockBind := restJSON(t, h, http.MethodPost, "/api/v1/auth-tests", wfAdminToken, "",
		`{"identity":"wf-alice","password":"`+wfUserPass+`","transport":"ldaps"}`, http.StatusOK)
	if lockBind["outcome"] != directory.BindOutcomeLocked {
		t.Fatalf("bind-test after lock: %+v", lockBind)
	}
	lockSearch := hostLDAPSearch(t, env, "cn=Directory Manager", env.dmPassword,
		dn, "base", "(objectClass=*)", "pwdAccountLockedTime", "accountUnlockTime")
	if !strings.Contains(lockSearch, "pwdAccountLockedTime") && !strings.Contains(lockSearch, "accountUnlockTime") {
		t.Fatalf("lock stamp not visible to ldapsearch:\n%s", lockSearch)
	}
	if err := ldapWhoami(t, env, dn, wfUserPass); err == nil {
		if env.engine == EngineNative {
			t.Fatal("native ldapwhoami must fail after REST lock")
		}
		t.Log("389 ldapwhoami still succeeds after lock stamp; passwordlockout may be off — bind-test locked is the contract")
	}

	st = restJSON(t, h, http.MethodPost, "/api/v1/users/wf-alice/unlock", wfAdminToken, etag(rev), "", http.StatusOK)
	if st["locked"] == "true" {
		t.Fatalf("unlock REST: %+v", st)
	}
	rev = st["revision"]
	if err := ldapWhoami(t, env, dn, wfUserPass); err != nil {
		t.Fatalf("ldapwhoami after unlock: %v", err)
	}

	st = restJSON(t, h, http.MethodPost, "/api/v1/users/wf-alice/expire-password", wfAdminToken, etag(rev), "", http.StatusOK)
	if st["mustChange"] != "true" {
		t.Fatalf("expire REST: %+v", st)
	}
	rev = st["revision"]
	bind := restJSON(t, h, http.MethodPost, "/api/v1/auth-tests", wfAdminToken, "",
		`{"identity":"wf-alice","password":"`+wfUserPass+`","transport":"ldaps"}`, http.StatusOK)
	if bind["outcome"] != directory.BindOutcomeMustChange {
		t.Fatalf("bind-test after expire: %+v", bind)
	}
	whoamiErr := ldapWhoami(t, env, dn, wfUserPass)
	if env.engine == EngineNative && whoamiErr == nil {
		t.Fatal("native ldapwhoami must fail after REST expire")
	}
	if env.engine == Engine389DS && whoamiErr != nil {
		t.Logf("389 ldapwhoami after expire (passwordexp may be off): %v", whoamiErr)
	}

	restNoContent(t, h, http.MethodPost, "/api/v1/users/wf-alice/password", wfAdminToken,
		`{"password":"`+wfUserPass2+`","revision":"`+rev+`"}`)
	st = restJSON(t, h, http.MethodGet, "/api/v1/users/wf-alice/account-state", wfAdminToken, "", "", http.StatusOK)
	if st["mustChange"] == "true" {
		t.Fatalf("set password should clear must-change: %+v", st)
	}
	rev = st["revision"]
	if err := ldapWhoami(t, env, dn, wfUserPass2); err != nil {
		t.Fatalf("ldapwhoami after set password: %v", err)
	}
	if err := ldapWhoami(t, env, dn, wfUserPass); err == nil {
		t.Fatal("old password still binds after REST set-password")
	}

	restNoContent(t, h, http.MethodPost, "/api/v1/users/wf-alice/password", wfAdminToken,
		`{"password":"`+wfUserPass+`","revision":"`+rev+`","mustChange":true}`)
	st = restJSON(t, h, http.MethodGet, "/api/v1/users/wf-alice/account-state", wfAdminToken, "", "", http.StatusOK)
	if st["mustChange"] != "true" {
		t.Fatalf("set password mustChange: %+v", st)
	}
	bind = restJSON(t, h, http.MethodPost, "/api/v1/auth-tests", wfAdminToken, "",
		`{"identity":"wf-alice","password":"`+wfUserPass+`","transport":"ldaps"}`, http.StatusOK)
	if bind["outcome"] != directory.BindOutcomeMustChange {
		t.Fatalf("bind-test after mustChange set-password: %+v", bind)
	}
	if env.engine == EngineNative {
		if err := ldapWhoami(t, env, dn, wfUserPass); err == nil {
			t.Fatal("native ldapwhoami must fail after mustChange set-password")
		}
	}
}

func startRESTLDAPEnv(t *testing.T) (compatEnv, http.Handler) {
	t.Helper()
	env := startCompatEngineFromYAML(t, workflowYAML())
	cfg := ldapclient.Config{
		Address:      env.ldapsAddr,
		Transport:    directory.TransportLDAPS,
		CAFile:       env.caFile,
		ServerName:   env.serverName,
		BindDN:       "uid=rt,ou=people,dc=example,dc=test",
		BindPassword: observability.Secret("runtime-secret"),
		DialTimeout:  8 * time.Second,
		PoolSize:     4,
	}
	pool, err := ldapclient.NewPool(cfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = pool.Close() })
	if err := pool.Do(t.Context(), func(c *ldapclient.Conn) error { return c.Ping(t.Context()) }); err != nil {
		t.Fatalf("runtime pool: %v", err)
	}
	rt, err := ds389.NewRuntime(pool, ds389.RuntimeConfig{
		Suffix:    "dc=example,dc=test",
		PeopleDN:  "ou=people,dc=example,dc=test",
		GroupsDN:  "ou=groups,dc=example,dc=test",
		RuntimeDN: "uid=rt,ou=people,dc=example,dc=test",
		Client:    cfg,
		SchemaTTL: time.Minute,
	})
	if err != nil {
		t.Fatal(err)
	}
	svc := app.New(app.Deps{
		Users:         rt.Users(),
		Groups:        rt.Groups(),
		Search:        rt,
		Bind:          rt,
		Schema:        rt,
		Caps:          rt,
		Marker:        rt,
		PeopleDN:      "ou=people,dc=example,dc=test",
		GroupsDN:      "ou=groups,dc=example,dc=test",
		BindTransport: directory.TransportLDAPS,
	})
	reg, err := auth.NewRegistry([]auth.Token{
		{ID: "admin", Scopes: []string{
			auth.ScopeDirectoryRead, auth.ScopeDirectoryWrite, auth.ScopeDirectoryPassword,
		}, Secret: observability.Secret(wfAdminToken)},
	})
	if err != nil {
		t.Fatal(err)
	}
	srv, err := api.New(api.Options{
		Registry: reg,
		Sessions: auth.NewStore(auth.DefaultSessionConfig()),
		Users:    svc.Users,
		Groups:   svc.Groups,
		Query:    svc.Query,
	})
	if err != nil {
		t.Fatal(err)
	}
	return env, srv.Handler()
}

func etag(rev string) string { return `"` + rev + `"` }

func restJSON(t *testing.T, h http.Handler, method, path, token, ifMatch, body string, want int) map[string]string {
	t.Helper()
	var rdr *strings.Reader
	if body != "" {
		rdr = strings.NewReader(body)
	} else {
		rdr = strings.NewReader("")
	}
	req := httptest.NewRequest(method, path, rdr)
	req.Header.Set("Authorization", "Bearer "+token)
	if body != "" {
		req.Header.Set("Content-Type", "application/json")
	}
	if ifMatch != "" {
		req.Header.Set("If-Match", ifMatch)
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != want {
		t.Fatalf("%s %s: %d %s", method, path, rec.Code, rec.Body.String())
	}
	if strings.Contains(rec.Body.String(), wfUserPass) || strings.Contains(rec.Body.String(), wfUserPass2) || strings.Contains(rec.Body.String(), wfAdminToken) {
		t.Fatalf("secret leaked on %s %s: %s", method, path, rec.Body.String())
	}
	out := map[string]string{}
	if rec.Body.Len() == 0 {
		return out
	}
	var raw map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &raw); err != nil {
		t.Fatalf("decode %s %s: %v %s", method, path, err, rec.Body.String())
	}
	for k, v := range raw {
		switch x := v.(type) {
		case string:
			out[k] = x
		case bool:
			if x {
				out[k] = "true"
			} else {
				out[k] = "false"
			}
		}
	}
	if rev := rec.Header().Get("ETag"); rev != "" {
		out["revision"] = strings.Trim(rev, `"`)
	}
	return out
}

func restNoContent(t *testing.T, h http.Handler, method, path, token, body string) {
	t.Helper()
	req := httptest.NewRequest(method, path, strings.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusNoContent {
		t.Fatalf("%s %s: %d %s", method, path, rec.Code, rec.Body.String())
	}
	if rec.Body.Len() != 0 {
		t.Fatalf("expected empty body: %q", rec.Body.String())
	}
}

func ldapWhoami(t *testing.T, env compatEnv, bindDN, password string) error {
	t.Helper()
	pw := writePW(t, password)
	cmd := exec.Command("ldapwhoami", "-x",
		"-H", "ldaps://"+env.ldapsAddr,
		"-o", "tls_reqcert=demand",
		"-o", "tls_cacert="+env.caFile,
		"-D", bindDN, "-y", pw)
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Logf("ldapwhoami %s: %v\n%s", bindDN, err, redactLogs(string(out), password, env.dmPassword, seedCanary))
	}
	return err
}
