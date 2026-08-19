//go:build integration

package dirsrv

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
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
	mdAdminToken = "lab-it-multidomain-admin-token-32"
	mdUserPass   = "region-bind-pass-12"
)

func multiDomainYAML() string {
	return `apiVersion: labldap.dev/v1alpha1
kind: LabScenario
metadata: { name: multidomain }
spec:
  directory:
    suffix: "dc=example,dc=test"
    additionalSuffixes:
      - "dc=region1,dc=example,dc=net"
      - "dc=region2,dc=example,dc=net"
      - "dc=region3,dc=example,dc=net"
  lifecycle: { startupMode: merge }
  transport: { ldaps: { enabled: true, port: 3636 } }
  runtimeAccount: { id: rt, passwordFile: secrets/runtime-ldap }
  users:
    - id: alice
      uid: alice
      passwordFile: secrets/user-alice
      enabled: true
      attributes: { sn: Seed }
  groups:
    - id: staff
      members:
        - user: alice
  passwordPolicy:
    minLength: 12
    historyCount: 0
    maxAge: 0s
    warningAge: 0s
    lockout: { enabled: true, maxFailures: 5, lockoutDuration: 60s }
    storageScheme: PBKDF2-SHA256
`
}

func startMultiDomainEnv(t *testing.T) (compatEnv, http.Handler) {
	t.Helper()
	env := startCompatEngineFromYAML(t, multiDomainYAML())
	extras := []string{
		"dc=region1,dc=example,dc=net",
		"dc=region2,dc=example,dc=net",
		"dc=region3,dc=example,dc=net",
	}
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
		Suffix:             "dc=example,dc=test",
		AdditionalSuffixes: extras,
		PeopleDN:           "ou=people,dc=example,dc=test",
		GroupsDN:           "ou=groups,dc=example,dc=test",
		RuntimeDN:          "uid=rt,ou=people,dc=example,dc=test",
		Client:             cfg,
		SchemaTTL:          time.Minute,
	})
	if err != nil {
		t.Fatal(err)
	}
	svc := app.New(app.Deps{
		Users:         rt.Users(),
		Groups:        rt.Groups(),
		Entries:       rt,
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
		}, Secret: observability.Secret(mdAdminToken)},
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
		Entries:  svc.Entries,
	})
	if err != nil {
		t.Fatal(err)
	}
	return env, srv.Handler()
}

func TestMultiDomainOUTreesAndExactDNs(t *testing.T) {
	requireHostTool(t, "ldapsearch")
	env, h := startMultiDomainEnv(t)
	t.Logf("engine=%s ldaps=%s", env.engine, env.ldapsAddr)

	suf := restRaw(t, h, http.MethodGet, "/api/v1/suffixes", mdAdminToken, "", "", http.StatusOK)
	var suffixes directory.SuffixList
	if err := json.Unmarshal(suf, &suffixes); err != nil {
		t.Fatal(err)
	}
	if suffixes.Primary != "dc=example,dc=test" || len(suffixes.Additional) != 3 {
		t.Fatalf("suffixes: %+v", suffixes)
	}

	for _, region := range []string{"region1", "region2", "region3"} {
		root := "dc=" + region + ",dc=example,dc=net"
		got := restRaw(t, h, http.MethodGet, "/api/v1/entries?dn="+url.QueryEscape(root), mdAdminToken, "", "", http.StatusOK)
		var ent directory.DirectoryEntry
		if err := json.Unmarshal(got, &ent); err != nil {
			t.Fatal(err)
		}
		if !directory.HasObjectClass(ent.ObjectClasses, "domain") {
			t.Fatalf("%s classes: %v", root, ent.ObjectClasses)
		}
	}

	r1 := "dc=region1,dc=example,dc=net"
	ous := []string{
		"ou=Region1," + r1,
		"ou=Network,ou=Region1," + r1,
		"ou=Shared,ou=Network,ou=Region1," + r1,
		"ou=ServiceUsers,ou=Shared,ou=Network,ou=Region1," + r1,
	}
	for _, dn := range ous {
		body := `{"dn":"` + dn + `","objectClasses":["organizationalUnit"]}`
		restRaw(t, h, http.MethodPost, "/api/v1/entries", mdAdminToken, "", body, http.StatusCreated)
	}
	alias := restRaw(t, h, http.MethodPost, "/api/v1/entries", mdAdminToken, "",
		`{"dn":"ou=AliasBox,ou=ServiceUsers,ou=Shared,ou=Network,ou=Region1,`+r1+`","objectClasses":["container"]}`,
		http.StatusCreated)
	var aliasEnt directory.DirectoryEntry
	if err := json.Unmarshal(alias, &aliasEnt); err != nil {
		t.Fatal(err)
	}
	if !directory.HasObjectClass(aliasEnt.ObjectClasses, "organizationalUnit") {
		t.Fatalf("container alias stored classes: %v", aliasEnt.ObjectClasses)
	}
	if directory.HasObjectClass(aliasEnt.ObjectClasses, "container") {
		t.Fatalf("literal container class must not be stored: %v", aliasEnt.ObjectClasses)
	}

	userDN := "cn=svc_bind_region1,ou=ServiceUsers,ou=Shared,ou=Network,ou=Region1," + r1
	created := restRaw(t, h, http.MethodPost, "/api/v1/users", mdAdminToken, "",
		`{"id":"svc_bind_region1","dn":"`+userDN+`","password":"`+mdUserPass+`","attributes":{"sn":"Bind","cn":"svc_bind_region1"}}`,
		http.StatusCreated)
	var user directory.User
	if err := json.Unmarshal(created, &user); err != nil {
		t.Fatal(err)
	}
	if !strings.EqualFold(user.DN, userDN) {
		t.Fatalf("user DN %q want %q", user.DN, userDN)
	}

	groupDN := "cn=region1-bind,ou=ServiceUsers,ou=Shared,ou=Network,ou=Region1," + r1
	graw := restRaw(t, h, http.MethodPost, "/api/v1/groups", mdAdminToken, "",
		`{"id":"region1-bind","dn":"`+groupDN+`","members":[{"kind":"user","id":"svc_bind_region1"}]}`,
		http.StatusCreated)
	var group directory.Group
	if err := json.Unmarshal(graw, &group); err != nil {
		t.Fatal(err)
	}
	if !strings.EqualFold(group.DN, groupDN) {
		t.Fatalf("group DN %q want %q", group.DN, groupDN)
	}

	memberOf := hostLDAPSearch(t, env, "cn=Directory Manager", env.dmPassword,
		user.DN, "base", "(objectClass=*)", "memberOf")
	if !strings.Contains(strings.ToLower(memberOf), "cn=region1-bind") {
		t.Fatalf("memberOf missing same-suffix group:\n%s", memberOf)
	}

	search := restRaw(t, h, http.MethodPost, "/api/v1/search", mdAdminToken, "",
		`{"base":"`+userDN+`","scope":"base","filter":"(objectClass=inetOrgPerson)","attributes":["cn","uid"]}`,
		http.StatusOK)
	if !strings.Contains(string(search), "svc_bind_region1") {
		t.Fatalf("search base miss: %s", search)
	}

	restRaw(t, h, http.MethodPost, "/api/v1/entries", mdAdminToken, "",
		`{"dn":"cn=evil,dc=evil,dc=com","objectClasses":["organizationalUnit"]}`,
		http.StatusForbidden)
	restRaw(t, h, http.MethodPost, "/api/v1/entries", mdAdminToken, "",
		`{"dn":"cn=config","objectClasses":["organizationalUnit"]}`,
		http.StatusForbidden)
	restRaw(t, h, http.MethodPost, "/api/v1/search", mdAdminToken, "",
		`{"base":"dc=evil,dc=com","scope":"sub","filter":"(objectClass=*)","attributes":["cn"]}`,
		http.StatusForbidden)
}

func restRaw(t *testing.T, h http.Handler, method, path, token, ifMatch, body string, want int) []byte {
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
	if strings.Contains(rec.Body.String(), mdUserPass) || strings.Contains(rec.Body.String(), mdAdminToken) {
		t.Fatalf("secret leaked on %s %s: %s", method, path, rec.Body.String())
	}
	return rec.Body.Bytes()
}
