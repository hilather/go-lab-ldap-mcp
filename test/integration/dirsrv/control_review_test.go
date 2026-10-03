//go:build integration

package dirsrv

import (
	"bytes"
	"encoding/json"
	"errors"
	"net/http"
	"net/url"
	"testing"
	"time"

	"github.com/hilather/go-lab-ldap-mcp/internal/app"
	"github.com/hilather/go-lab-ldap-mcp/internal/apperr"
	"github.com/hilather/go-lab-ldap-mcp/internal/directory"
	"github.com/hilather/go-lab-ldap-mcp/internal/directory/ds389"
	"github.com/hilather/go-lab-ldap-mcp/internal/directory/ldapclient"
	"github.com/hilather/go-lab-ldap-mcp/internal/observability"
)

func TestControlReviewProtectsAliasesFiltersAndExportBounds(t *testing.T) {
	rt := startControlReviewRuntime(t)
	svc := app.New(app.Deps{Users: rt.Users(), Entries: rt, Search: rt})
	writer := app.Principal{Kind: app.KindToken, ID: "writer", Scopes: directory.ScopeSet{"directory:write"}}
	reader := app.Principal{Kind: app.KindToken, ID: "reader", Scopes: directory.ScopeSet{"directory:read"}}
	user, err := rt.Users().Get(t.Context(), "alice")
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"userPassword;binary", "2.5.4.35", "2.5.4.35;binary", "nsAccountLock;binary", "2.16.840.1.113730.3.1.55"} {
		_, err := svc.Users.Update(t.Context(), writer, "alice", app.UpdateUser{Revision: user.Revision, UserPatch: directory.UserPatch{Attributes: map[string]string{name: "unauthorized-replacement"}}})
		if err == nil || apperr.CodeOf(err) != apperr.CodeConfiguration {
			t.Fatalf("user alias %s bypassed policy: %v", name, err)
		}
		_, err = svc.Entries.Update(t.Context(), writer, directory.EntryPatch{DN: user.DN, Revision: user.Revision, Changes: []directory.EntryChange{{Name: name, Op: "replace", Values: []string{"unauthorized-replacement"}}}})
		if err == nil || apperr.CodeOf(err) != apperr.CodeConfiguration {
			t.Fatalf("entry alias %s bypassed policy: %v", name, err)
		}
	}
	// Ordinary profile attributes remain editable by directory:write.
	if _, err := svc.Users.Update(t.Context(), writer, "alice", app.UpdateUser{Revision: user.Revision, UserPatch: directory.UserPatch{Attributes: map[string]string{"description": "allowed"}}}); err != nil {
		t.Fatal(err)
	}
	result, err := rt.BindTest(t.Context(), "alice", observability.Secret(seedCanary), directory.TransportLDAPS)
	if err != nil || result.Outcome != directory.BindOutcomeSuccess {
		t.Fatalf("unauthorized alias changed password/account: %v %s", err, result.Outcome)
	}
	for _, filter := range []string{"(userPassword=*)", "(userPassword=prefix*)", "(2.5.4.35=*)", "(userPassword;binary=*)", "(userPassword:octetStringMatch:=x)", "(:octetStringMatch:=x)"} {
		_, err := svc.Query.Search(t.Context(), reader, directory.SearchQuery{Base: "ou=people,dc=example,dc=test", Scope: "sub", Filter: filter})
		if err == nil || apperr.CodeOf(err) != apperr.CodeConfiguration {
			t.Fatalf("secret inference filter %s: %v", filter, err)
		}
	}
	if _, err := svc.Query.Search(t.Context(), reader, directory.SearchQuery{Base: "ou=people,dc=example,dc=test", Scope: "sub", Filter: "(uid=alice)"}); err != nil {
		t.Fatal(err)
	}
	var out bytes.Buffer
	if err := rt.Export(t.Context(), &out, directory.ExportOptions{MaxEntries: 1, OmitSecrets: true}); err == nil || out.Len() != 0 {
		t.Fatalf("entry cap: err=%v bytes=%d", err, out.Len())
	}
	if err := rt.Export(t.Context(), &out, directory.ExportOptions{MaxBytes: 1, OmitSecrets: true}); err == nil || out.Len() != 0 {
		t.Fatalf("header byte cap: err=%v bytes=%d", err, out.Len())
	}
	if err := rt.Export(t.Context(), &out, directory.ExportOptions{OmitSecrets: true}); err != nil {
		t.Fatal(err)
	}
}

func TestControlReviewResetClearsAdditionalSuffixesAndPreservesRoots(t *testing.T) {
	_, h := startMultiDomainEnv(t)
	suffix := "dc=region1,dc=example,dc=net"
	for _, dn := range []string{"ou=parent," + suffix, "ou=child,ou=parent," + suffix} {
		raw, _ := json.Marshal(directory.EntrySpec{DN: dn, ObjectClasses: []string{"organizationalUnit"}})
		restRaw(t, h, http.MethodPost, "/api/v1/entries", mdAdminToken, "", string(raw), http.StatusCreated)
	}
	baselineRaw := restRaw(t, h, http.MethodGet, "/api/v1/baseline", mdAdminToken, "", "", http.StatusOK)
	var baseline app.Baseline
	if err := json.Unmarshal(baselineRaw, &baseline); err != nil {
		t.Fatal(err)
	}
	raw, _ := json.Marshal(app.ResetRequest{Name: "multidomain", ExpectedRevision: baseline.ExpectedRevision})
	result := restRaw(t, h, http.MethodPost, "/api/v1/reset", mdAdminToken, "", string(raw), http.StatusAccepted)
	var status app.ResetStatus
	if err := json.Unmarshal(result, &status); err != nil {
		t.Fatal(err)
	}
	if status.State != "Ready" || status.Counts.Extra != 2 {
		t.Fatalf("additional reset failed: %+v", status)
	}
	restRaw(t, h, http.MethodGet, "/api/v1/entries?dn="+url.QueryEscape(suffix), mdAdminToken, "", "", http.StatusOK)
	restRaw(t, h, http.MethodGet, "/api/v1/entries?dn="+url.QueryEscape("ou=parent,"+suffix), mdAdminToken, "", "", http.StatusNotFound)
}

func startControlReviewRuntime(t *testing.T) *ds389.Runtime {
	t.Helper()
	env := startCompatEngine(t)
	cfg := ldapclient.Config{Address: env.ldapsAddr, Transport: directory.TransportLDAPS, CAFile: env.caFile, ServerName: env.serverName, BindDN: "uid=rt,ou=people,dc=example,dc=test", BindPassword: observability.Secret("runtime-secret"), DialTimeout: 8 * time.Second, PoolSize: 4}
	pool, err := ldapclient.NewPool(cfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = pool.Close() })
	rt, err := ds389.NewRuntime(pool, ds389.RuntimeConfig{Suffix: "dc=example,dc=test", PeopleDN: "ou=people,dc=example,dc=test", GroupsDN: "ou=groups,dc=example,dc=test", RuntimeDN: "uid=rt,ou=people,dc=example,dc=test", Client: cfg})
	if err != nil {
		t.Fatal(err)
	}
	return rt
}

func TestControlReviewAccountRevisionsRejectStaleStateChanges(t *testing.T) {
	rt := startControlReviewRuntime(t)
	repo := rt.Users()
	initial, err := repo.Get(t.Context(), "alice")
	if err != nil {
		t.Fatal(err)
	}
	locked, err := repo.Lock(t.Context(), "alice", initial.Revision)
	if err != nil {
		t.Fatal(err)
	}
	if !locked.Locked || locked.Revision == initial.Revision {
		t.Fatal("lock did not change revision")
	}
	fresh, err := repo.Get(t.Context(), "alice")
	if err != nil {
		t.Fatal(err)
	}
	if fresh.Revision != locked.Revision {
		t.Fatal("user/account revisions disagree after lock")
	}
	_, err = repo.Unlock(t.Context(), "alice", initial.Revision)
	assertControlRevisionConflict(t, err)
	unlocked, err := repo.Unlock(t.Context(), "alice", fresh.Revision)
	if err != nil {
		t.Fatal(err)
	}
	expired, err := repo.ExpirePassword(t.Context(), "alice", unlocked.Revision)
	if err != nil {
		t.Fatal(err)
	}
	if !expired.MustChange || expired.Revision == unlocked.Revision {
		t.Fatal("expiry did not change revision")
	}
	fresh, err = repo.Get(t.Context(), "alice")
	if err != nil {
		t.Fatal(err)
	}
	if fresh.Revision != expired.Revision {
		t.Fatal("user/account revisions disagree after expiry")
	}
	_, err = repo.ClearPasswordExpiry(t.Context(), "alice", unlocked.Revision)
	assertControlRevisionConflict(t, err)
	clear, err := repo.ClearPasswordExpiry(t.Context(), "alice", expired.Revision)
	if err != nil {
		t.Fatal(err)
	}
	if clear.MustChange {
		t.Fatal("fresh clear-expiry did not clear")
	}
}

func assertControlRevisionConflict(t *testing.T, err error) {
	t.Helper()
	var structured *apperr.Error
	if !errors.As(err, &structured) {
		t.Fatalf("missing structured revision conflict: %v", err)
	}
	for _, field := range structured.Fields() {
		if field.Path == "revision" && field.Code == directory.FieldConflict {
			return
		}
	}
	t.Fatalf("expected revision conflict: %v", err)
}
