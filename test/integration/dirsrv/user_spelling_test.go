//go:build integration

package dirsrv

import (
	"strings"
	"testing"

	"github.com/hilather/go-lab-ldap-mcp/internal/app"
	"github.com/hilather/go-lab-ldap-mcp/internal/config"
	"github.com/hilather/go-lab-ldap-mcp/internal/directory"
)

// TestUserViewRoundTripsWithOptionedPlannedValues is engine-neutral: a user
// carrying an optioned cn (written through the entry API) still round-trips
// through the user API, because the user view only returns spellings the
// user write rule accepts. On native, which stores cn;lang-en as an opaque
// attribute and never returns it for a cn request, the hiding half is
// trivially true; the round-trip half is meaningful on both engines.
func TestUserViewRoundTripsWithOptionedPlannedValues(t *testing.T) {
	rt := startControlReviewRuntime(t)
	svc := app.New(app.Deps{Users: rt.Users(), Entries: rt, Search: rt})
	writer := app.Principal{Kind: app.KindToken, ID: "writer", Scopes: directory.ScopeSet{"directory:read", "directory:write"}}

	ent, err := svc.Entries.Get(t.Context(), writer, "uid=alice,ou=people,dc=example,dc=test")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := svc.Entries.Update(t.Context(), writer, directory.EntryPatch{DN: ent.DN, Revision: ent.Revision, Changes: []directory.EntryChange{{Name: "cn;lang-en", Op: "add", Values: []string{"Alice EN"}}}}); err != nil {
		t.Fatalf("entry API add cn;lang-en: %v", err)
	}
	user, err := svc.Users.Get(t.Context(), writer, "alice")
	if err != nil {
		t.Fatal(err)
	}
	attrs := map[string]string{}
	for _, kv := range user.Attributes {
		if config.ForbiddenUserWriteAttr(kv.Name) {
			t.Fatalf("user view carries unwritable name %q", kv.Name)
		}
		attrs[kv.Name] = kv.Value
	}
	attrs["description"] = "round-trip"
	if _, err := svc.Users.Update(t.Context(), writer, "alice", app.UpdateUser{Revision: user.Revision, UserPatch: directory.UserPatch{Attributes: attrs}}); err != nil {
		t.Fatalf("round-trip save of the user view: %v", err)
	}
}

// TestEntryCreateDropsPlannedSpellings: entry create with inetOrgPerson
// drops option/alias spellings of the planned names and writes the planned
// values; protected spellings are still rejected (engine-neutral).
func TestEntryCreateDropsPlannedSpellings(t *testing.T) {
	rt := startControlReviewRuntime(t)
	svc := app.New(app.Deps{Users: rt.Users(), Entries: rt, Search: rt})
	writer := app.Principal{Kind: app.KindToken, ID: "writer", Scopes: directory.ScopeSet{"directory:read", "directory:write"}}
	dn := "uid=carol,ou=people,dc=example,dc=test"
	ent, err := svc.Entries.Create(t.Context(), writer, directory.EntrySpec{DN: dn, ObjectClasses: []string{"inetOrgPerson"}, Attributes: map[string]string{
		"commonName": "Alias", "cn;lang-en": "Optioned", "userid": "other", "mail": "carol@example.test",
	}})
	if err != nil {
		t.Fatalf("entry create: %v", err)
	}
	var mail bool
	for _, kv := range ent.Attributes {
		name := strings.ToLower(kv.Name)
		switch {
		case name == "commonname" || name == "userid" || strings.HasPrefix(name, "cn;"):
			t.Fatalf("planned spelling %s was written", kv.Name)
		case name == "cn" && kv.Value != "carol":
			t.Fatalf("cn = %q, want the planned RDN value", kv.Value)
		case name == "uid" && kv.Value != "carol":
			t.Fatalf("uid = %q, want the planned RDN value", kv.Value)
		case name == "mail":
			mail = true
		}
	}
	if !mail {
		t.Fatalf("ordinary extra attribute dropped: %#v", ent.Attributes)
	}
	if _, err := svc.Entries.Create(t.Context(), writer, directory.EntrySpec{DN: "uid=dave,ou=people,dc=example,dc=test", ObjectClasses: []string{"inetOrgPerson"}, Attributes: map[string]string{"cn": "Dave", "userPassword;lang-en": "nope"}}); err == nil {
		t.Fatal("protected optioned name must be rejected on entry create")
	}
}
