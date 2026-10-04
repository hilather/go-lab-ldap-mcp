//go:build integration

package dirsrv

import (
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/go-ldap/ldap/v3"

	"github.com/hilather/go-lab-ldap-mcp/internal/app"
	"github.com/hilather/go-lab-ldap-mcp/internal/apperr"
	"github.com/hilather/go-lab-ldap-mcp/internal/bootstrap"
	"github.com/hilather/go-lab-ldap-mcp/internal/config"
	"github.com/hilather/go-lab-ldap-mcp/internal/directory"
	"github.com/hilather/go-lab-ldap-mcp/internal/directory/ds389"
	"github.com/hilather/go-lab-ldap-mcp/internal/directory/ldapclient"
	"github.com/hilather/go-lab-ldap-mcp/internal/observability"
)

// Second descriptors rfc822Mailbox and gn (#18 follow-up) must behave the
// same on both engines through the user API (REST/MCP share app.Users),
// the entry API and YAML seeding: writes send the primary names mail and
// givenName, the user view shows mail/givenname, and a second merge apply of
// an alias-spelled YAML user reports it Matched.

func aliasYAML() string {
	return strings.Replace(seedYAML("merge"), "attributes: { sn: Seed }", "attributes: { sn: Seed, rfc822Mailbox: alice@example.test, gn: Alice }", 1)
}

func aliasRuntime(t *testing.T, env compatEnv) *ds389.Runtime {
	t.Helper()
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

// reseedAliasYAML runs the shared bootstrap seed (ds389.Engine, used by both
// engines) again for aliasYAML, as a second merge apply would.
func reseedAliasYAML(t *testing.T, env compatEnv) bootstrap.SeedResult {
	t.Helper()
	dir := t.TempDir()
	sec := filepath.Join(dir, "secrets")
	if err := os.Mkdir(sec, 0o700); err != nil {
		t.Fatal(err)
	}
	for name, val := range map[string]string{"runtime-ldap": "runtime-secret", "user-alice": seedCanary} {
		if err := os.WriteFile(filepath.Join(sec, name), []byte(val+"\n"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	yaml := withITEngine(aliasYAML())
	compiled, err := config.Compile(t.Context(), []byte(yaml), filepath.Join(dir, "lab.yaml"), config.LoadOptions{Caller: config.CallerBootstrap, Secrets: config.DirSecretResolver(dir)})
	if err != nil {
		t.Fatalf("compile alias scenario: %v", err)
	}
	nrm := compiled.Normalized
	res, err := ds389.Engine{}.ReconcileSeed(t.Context(), bootstrap.SeedRequest{
		TreeRequest: bootstrap.TreeRequest{
			Suffix: compiled.Engine.Suffix, PeopleDN: nrm.PeopleDN.String(), GroupsDN: nrm.GroupsDN.String(),
			RuntimeDN: nrm.Runtime.DN, RuntimePassword: nrm.Runtime.Password.Value,
			DMPassword: observability.Secret(env.dmPassword), LDAPURL: "ldaps://" + env.ldapsAddr,
			CAFile: env.caFile, Host: env.serverName, Write: true,
		},
		Users: nrm.Users, Groups: nrm.Groups, StartupMode: nrm.StartupMode,
	})
	if err != nil {
		t.Fatalf("second seed apply: %v", err)
	}
	return res
}

func userAttrValues(t *testing.T, svc *app.Services, p app.Principal, id string) (directory.User, map[string][]string) {
	t.Helper()
	u, err := svc.Users.Get(t.Context(), p, directory.UserID(id))
	if err != nil {
		t.Fatal(err)
	}
	out := map[string][]string{}
	for _, kv := range u.Attributes {
		out[kv.Name] = append(out[kv.Name], kv.Value)
	}
	return u, out
}

func entryAttrValues(t *testing.T, svc *app.Services, p app.Principal, dn string) (directory.DirectoryEntry, map[string][]string) {
	t.Helper()
	e, err := svc.Entries.Get(t.Context(), p, dn)
	if err != nil {
		t.Fatal(err)
	}
	out := map[string][]string{}
	for _, kv := range e.Attributes {
		out[strings.ToLower(kv.Name)] = append(out[strings.ToLower(kv.Name)], kv.Value)
	}
	return e, out
}

func wantDuplicate(t *testing.T, err error, field string) {
	t.Helper()
	var e *apperr.Error
	if err == nil || !errors.As(err, &e) || len(e.Fields()) != 1 || e.Fields()[0].Code != "duplicate_attribute" || e.Fields()[0].Path != field {
		t.Fatalf("want duplicate_attribute at %s, got %v", field, err)
	}
}

func TestMailAndGivenNameAliasesAreEngineNeutral(t *testing.T) {
	env := startCompatEngineFromYAML(t, aliasYAML())
	rt := aliasRuntime(t, env)
	svc := app.New(app.Deps{Users: rt.Users(), Entries: rt, Search: rt})
	writer := app.Principal{Kind: app.KindToken, ID: "writer", Scopes: directory.ScopeSet{"directory:read", "directory:write", "directory:password"}}
	const aliceDN = "uid=alice,ou=people,dc=example,dc=test"

	// YAML seed: alias spellings land under the primary names, and a second
	// merge apply reports the user Matched.
	if _, attrs := userAttrValues(t, svc, writer, "alice"); !slices.Equal(attrs["mail"], []string{"alice@example.test"}) || !slices.Equal(attrs["givenname"], []string{"Alice"}) {
		t.Fatalf("seeded alias user view = %v", attrs)
	}
	if res := reseedAliasYAML(t, env); !slices.Contains(res.Matched, aliceDN) || slices.Contains(res.Updated, aliceDN) {
		t.Fatalf("second apply must match alice: %+v", res)
	}

	// PATCH {"gn": ""} removes the YAML-seeded value (stored as givenname on
	// native); after a reseed re-adds it, PATCH {"givenName": ""} does too.
	for _, name := range []string{"gn", "givenName"} {
		u, attrs := userAttrValues(t, svc, writer, "alice")
		if len(attrs["givenname"]) == 0 {
			if res := reseedAliasYAML(t, env); !slices.Contains(res.Updated, aliceDN) {
				t.Fatalf("reseed must restore givenName: %+v", res)
			}
			u, _ = userAttrValues(t, svc, writer, "alice")
		}
		if _, err := svc.Users.Update(t.Context(), writer, "alice", app.UpdateUser{Revision: u.Revision, UserPatch: directory.UserPatch{Attributes: map[string]string{name: ""}}}); err != nil {
			t.Fatalf("PATCH %s empty: %v", name, err)
		}
		if _, attrs := userAttrValues(t, svc, writer, "alice"); len(attrs["givenname"]) != 0 {
			t.Fatalf("PATCH {%q: \"\"} left givenname: %v", name, attrs)
		}
	}

	// User create (REST/MCP path) with alias spellings, and the duplicate rule.
	if _, err := svc.Users.Create(t.Context(), writer, app.CreateUser{ID: "bob", Password: observability.Secret("Alias-Bob-Pw-0001"), Attributes: map[string]string{"sn": "Bob", "rfc822Mailbox": "bob@example.test", "gn": "Bob"}}); err != nil {
		t.Fatalf("create with aliases: %v", err)
	}
	if _, attrs := userAttrValues(t, svc, writer, "bob"); !slices.Equal(attrs["mail"], []string{"bob@example.test"}) || !slices.Equal(attrs["givenname"], []string{"Bob"}) {
		t.Fatalf("alias-created user view = %v", attrs)
	}
	_, err := svc.Users.Create(t.Context(), writer, app.CreateUser{ID: "dup", Password: observability.Secret("Alias-Dup-Pw-00001"), Attributes: map[string]string{"sn": "D", "mail": "a@example.test", "rfc822Mailbox": "b@example.test"}})
	wantDuplicate(t, err, "attributes.rfc822Mailbox")

	// Entry API: create with only the alias stores mail; a pair keeps mail's
	// value; update add gn stores givenName.
	const carolDN = "uid=carol,ou=people,dc=example,dc=test"
	if _, err := svc.Entries.Create(t.Context(), writer, directory.EntrySpec{DN: carolDN, ObjectClasses: []string{"inetOrgPerson"}, Attributes: map[string]string{"sn": "C", "rfc822Mailbox": "carol@example.test"}}); err != nil {
		t.Fatalf("entry create with alias: %v", err)
	}
	ent, attrs := entryAttrValues(t, svc, writer, carolDN)
	if !slices.Equal(attrs["mail"], []string{"carol@example.test"}) || len(attrs["rfc822mailbox"]) != 0 {
		t.Fatalf("entry alias create = %v", attrs)
	}
	if _, err := svc.Entries.Update(t.Context(), writer, directory.EntryPatch{DN: carolDN, Revision: ent.Revision, Changes: []directory.EntryChange{{Name: "gn", Op: "add", Values: []string{"Carol"}}}}); err != nil {
		t.Fatalf("entry add gn: %v", err)
	}
	if _, attrs = entryAttrValues(t, svc, writer, carolDN); !slices.Equal(attrs["givenname"], []string{"Carol"}) || len(attrs["gn"]) != 0 {
		t.Fatalf("entry add gn = %v", attrs)
	}
	const daveDN = "uid=dave,ou=people,dc=example,dc=test"
	if _, err := svc.Entries.Create(t.Context(), writer, directory.EntrySpec{DN: daveDN, ObjectClasses: []string{"inetOrgPerson"}, Attributes: map[string]string{"sn": "D", "mail": "first@example.test", "rfc822Mailbox": "second@example.test"}}); err != nil {
		t.Fatalf("entry create with pair: %v", err)
	}
	if _, attrs = entryAttrValues(t, svc, writer, daveDN); !slices.Equal(attrs["mail"], []string{"first@example.test"}) {
		t.Fatalf("entry pair create kept %v, want mail's value", attrs["mail"])
	}
}

// TestLegacyAliasAttributeDelete pins parity delta D35: an entry-API delete
// of a second-descriptor spelling keeps the client's spelling. On native a
// legacy attribute stored under the alias (direct LDAP write, D17) is
// removed without touching mail, and the user view never shows it; on 389
// the alias is the mail type itself.
func TestLegacyAliasAttributeDelete(t *testing.T) {
	env := startCompatEngine(t)
	rt := aliasRuntime(t, env)
	svc := app.New(app.Deps{Users: rt.Users(), Entries: rt, Search: rt})
	writer := app.Principal{Kind: app.KindToken, ID: "writer", Scopes: directory.ScopeSet{"directory:read", "directory:write"}}
	const aliceDN = "uid=alice,ou=people,dc=example,dc=test"

	u, err := svc.Users.Get(t.Context(), writer, "alice")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := svc.Users.Update(t.Context(), writer, "alice", app.UpdateUser{Revision: u.Revision, UserPatch: directory.UserPatch{Attributes: map[string]string{"mail": "real@example.test"}}}); err != nil {
		t.Fatal(err)
	}
	dm := dialDM(t, env)
	// Native stores this as an unknown attribute (D17). When PR-2C retires
	// D17, native will resolve or reject it: update this native branch and
	// the D35 row together.
	mod := ldap.NewModifyRequest(aliceDN, nil)
	mod.Add("rfc822Mailbox", []string{"legacy@example.test"})
	if err := dm.Modify(mod); err != nil {
		t.Fatalf("direct LDAP legacy write: %v", err)
	}
	native := env.engine == EngineNative

	_, view := userAttrValues(t, svc, writer, "alice")
	_, ent := entryAttrValues(t, svc, writer, aliceDN)
	if native {
		if !slices.Equal(view["mail"], []string{"real@example.test"}) || !slices.Equal(ent["rfc822mailbox"], []string{"legacy@example.test"}) {
			t.Fatalf("native: user view %v must show only the real mail; entry %v keeps the legacy attribute", view, ent)
		}
	} else if len(view["mail"]) != 2 || len(ent["rfc822mailbox"]) != 0 {
		t.Fatalf("389: the alias is mail itself; view %v entry %v", view, ent)
	}

	// Replace of the alias writes mail on both engines; native keeps the
	// legacy attribute (D35 / user-guide note: delete legacy rows, do not
	// replace them).
	e, _ := entryAttrValues(t, svc, writer, aliceDN)
	if _, err := svc.Entries.Update(t.Context(), writer, directory.EntryPatch{DN: aliceDN, Revision: e.Revision, Changes: []directory.EntryChange{{Name: "rfc822Mailbox", Op: "replace", Values: []string{"new@example.test"}}}}); err != nil {
		t.Fatalf("entry replace alias: %v", err)
	}
	e, ent = entryAttrValues(t, svc, writer, aliceDN)
	if !slices.Equal(ent["mail"], []string{"new@example.test"}) {
		t.Fatalf("replace alias must write mail: %v", ent)
	}
	if native && !slices.Equal(ent["rfc822mailbox"], []string{"legacy@example.test"}) {
		t.Fatalf("native replace must leave the legacy attribute: %v", ent)
	}

	// Delete keeps the client's spelling.
	if _, err := svc.Entries.Update(t.Context(), writer, directory.EntryPatch{DN: aliceDN, Revision: e.Revision, Changes: []directory.EntryChange{{Name: "rfc822Mailbox", Op: "delete"}}}); err != nil {
		t.Fatalf("entry delete alias: %v", err)
	}
	_, ent = entryAttrValues(t, svc, writer, aliceDN)
	if native {
		if len(ent["rfc822mailbox"]) != 0 || !slices.Equal(ent["mail"], []string{"new@example.test"}) {
			t.Fatalf("native delete of the alias must remove only the legacy attribute: %v", ent)
		}
	} else if len(ent["mail"]) != 0 {
		t.Fatalf("389 delete of the alias removes mail: %v", ent)
	}
}

// TestOptionedAliasDeleteRoundTrip pins the optioned branch of parity delta
// D35: an entry-API add of rfc822Mailbox;lang-en stores mail;lang-en, and a
// delete of the same spelling removes it on both engines without touching
// bare mail. On native a legacy row stored under the optioned alias is
// removed first and alone, and a bare alias delete with no legacy row
// answers conflict on attribute (noSuchAttribute) with mail untouched.
func TestOptionedAliasDeleteRoundTrip(t *testing.T) {
	env := startCompatEngine(t)
	rt := aliasRuntime(t, env)
	svc := app.New(app.Deps{Users: rt.Users(), Entries: rt, Search: rt})
	writer := app.Principal{Kind: app.KindToken, ID: "writer", Scopes: directory.ScopeSet{"directory:read", "directory:write"}}
	const aliceDN = "uid=alice,ou=people,dc=example,dc=test"
	native := env.engine == EngineNative

	u, err := svc.Users.Get(t.Context(), writer, "alice")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := svc.Users.Update(t.Context(), writer, "alice", app.UpdateUser{Revision: u.Revision, UserPatch: directory.UserPatch{Attributes: map[string]string{"mail": "real@example.test"}}}); err != nil {
		t.Fatal(err)
	}
	update := func(ch directory.EntryChange) error {
		t.Helper()
		e, _ := entryAttrValues(t, svc, writer, aliceDN)
		_, err := svc.Entries.Update(t.Context(), writer, directory.EntryPatch{DN: aliceDN, Revision: e.Revision, Changes: []directory.EntryChange{ch}})
		return err
	}

	if err := update(directory.EntryChange{Name: "rfc822Mailbox;lang-en", Op: "add", Values: []string{"en@example.test"}}); err != nil {
		t.Fatalf("add optioned alias: %v", err)
	}
	if _, ent := entryAttrValues(t, svc, writer, aliceDN); !slices.Equal(ent["mail;lang-en"], []string{"en@example.test"}) {
		t.Fatalf("optioned alias add must store mail;lang-en: %v", ent)
	}
	if err := update(directory.EntryChange{Name: "rfc822Mailbox;lang-en", Op: "delete"}); err != nil {
		t.Fatalf("delete optioned alias: %v", err)
	}
	if _, ent := entryAttrValues(t, svc, writer, aliceDN); len(ent["mail;lang-en"]) != 0 || !slices.Equal(ent["mail"], []string{"real@example.test"}) {
		t.Fatalf("optioned alias delete must remove mail;lang-en only: %v", ent)
	}
	if !native {
		return
	}

	// Native legacy row under the optioned alias (direct LDAP, D17) next
	// to a real mail;lang-en: the delete removes only the legacy row.
	if err := update(directory.EntryChange{Name: "mail;lang-en", Op: "add", Values: []string{"real-en@example.test"}}); err != nil {
		t.Fatal(err)
	}
	dm := dialDM(t, env)
	mod := ldap.NewModifyRequest(aliceDN, nil)
	mod.Add("rfc822Mailbox;lang-en", []string{"legacy-en@example.test"})
	if err := dm.Modify(mod); err != nil {
		t.Fatalf("direct LDAP legacy write: %v", err)
	}
	if err := update(directory.EntryChange{Name: "RFC822Mailbox;LANG-EN", Op: "delete"}); err != nil {
		t.Fatalf("delete optioned legacy alias: %v", err)
	}
	_, ent := entryAttrValues(t, svc, writer, aliceDN)
	if len(ent["rfc822mailbox;lang-en"]) != 0 || !slices.Equal(ent["mail;lang-en"], []string{"real-en@example.test"}) || !slices.Equal(ent["mail"], []string{"real@example.test"}) {
		t.Fatalf("native optioned legacy delete must remove only the legacy row: %v", ent)
	}

	// Bare alias with no legacy row: D35 keeps the spelling, native answers
	// noSuchAttribute (conflict on attribute) and mail stays.
	err = update(directory.EntryChange{Name: "rfc822Mailbox", Op: "delete"})
	var ae *apperr.Error
	if !errors.As(err, &ae) || len(ae.Fields()) != 1 || ae.Fields()[0].Path != "attribute" || ae.Fields()[0].Code != directory.FieldConflict {
		t.Fatalf("native bare alias delete without a legacy row: want attribute/conflict, got %v", err)
	}
	if _, ent := entryAttrValues(t, svc, writer, aliceDN); !slices.Equal(ent["mail"], []string{"real@example.test"}) {
		t.Fatalf("native bare alias delete must not touch mail: %v", ent)
	}
}
