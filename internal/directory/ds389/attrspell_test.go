package ds389

import (
	"testing"

	"github.com/go-ldap/ldap/v3"

	"github.com/hilather/go-lab-ldap-mcp/internal/config"
	"github.com/hilather/go-lab-ldap-mcp/internal/directory"
)

func TestSkipPlannedUserAttrRecognisesEverySpelling(t *testing.T) {
	for _, name := range []string{"cn;lang-en", "commonName", "SURNAME", "userid", "uid;x-a", "2.5.4.0", "objectClass", "userPassword;lang-en"} {
		if !skipPlannedUserAttr(name) {
			t.Fatalf("%s must be skipped", name)
		}
	}
	if skipPlannedUserAttr("mail") || skipPlannedUserAttr("mail;lang-en") {
		t.Fatal("ordinary attributes must not be skipped")
	}
}

func TestEntryAddAttrsDropsPlannedSpellingsAfterForbiddenCheck(t *testing.T) {
	dn, err := config.ParseDN("uid=alice,ou=people,dc=example,dc=test")
	if err != nil {
		t.Fatal(err)
	}
	attrs, err := entryAddAttrs(dn, directory.ClassInetOrgPerson, map[string]string{
		"commonName": "Alias", "cn;lang-en": "Opt", "2.5.4.0": "extensibleObject", "mail": "a@example.test", "Mail": "b@example.test",
	})
	if err != nil {
		t.Fatal(err)
	}
	var extras []string
	for _, a := range attrs {
		switch a.Type {
		case "objectClass", "uid", "cn", "sn":
			continue
		}
		extras = append(extras, a.Type)
	}
	if len(extras) != 1 || config.CanonicalAttr(extras[0]) != "mail" {
		t.Fatalf("extras = %v", extras)
	}
	if _, err := entryAddAttrs(dn, directory.ClassInetOrgPerson, map[string]string{"cn": "x", "userPassword;lang-en": "secret"}); err == nil {
		t.Fatal("forbidden optioned name must be rejected even next to planned names")
	}
}

func TestUserFromEntryHidesOptionedAndRenamesAliases(t *testing.T) {
	e := ldap.NewEntry("uid=alice,ou=people,dc=example,dc=test", map[string][]string{
		"uid":        {"alice"},
		"commonName": {"Alice"},
		"cn;lang-en": {"Alice EN"},
		"userid":     {"alice"},
		"mail":       {"a@example.test"},
	})
	u := userFromEntry(e, "ou=groups,dc=example,dc=test")
	for _, kv := range u.Attributes {
		if config.ForbiddenUserWriteAttr(kv.Name) {
			t.Fatalf("user view carries unwritable name %q", kv.Name)
		}
	}
	found := map[string]bool{}
	for _, kv := range u.Attributes {
		found[kv.Name] = true
	}
	if !found["cn"] || !found["mail"] || found["uid"] {
		t.Fatalf("attributes = %#v", u.Attributes)
	}
}

func TestEntryAddAttrsSendsPrimaryNamesForMailAndGivenName(t *testing.T) {
	dn, err := config.ParseDN("uid=alice,ou=people,dc=example,dc=test")
	if err != nil {
		t.Fatal(err)
	}
	attrs, err := entryAddAttrs(dn, directory.ClassInetOrgPerson, map[string]string{
		"rfc822Mailbox": "a@example.test", "GN": "Upper", "givenName": "Alice", "gn": "lower",
	})
	if err != nil {
		t.Fatal(err)
	}
	got := map[string][]string{}
	for _, a := range attrs {
		switch a.Type {
		case "objectClass", "uid", "cn", "sn":
			continue
		}
		got[a.Type] = a.Vals
	}
	if len(got) != 2 || len(got["mail"]) != 1 || got["mail"][0] != "a@example.test" || len(got["givenName"]) != 1 || got["givenName"][0] != "Alice" {
		t.Fatalf("extras = %v (want mail and the givenName value, first in case-insensitive order)", got)
	}
}

func TestApplyEntryChangeKeepsClientSpellingOnDeleteOnly(t *testing.T) {
	for op, want := range map[string]string{directory.EntryModReplace: "givenName", directory.EntryModAdd: "givenName", directory.EntryModDelete: "gn"} {
		mod := ldap.NewModifyRequest("uid=alice,ou=people,dc=example,dc=test", nil)
		if err := applyEntryChange(mod, directory.EntryChange{Op: op, Name: "gn", Values: []string{"x"}}, nil); err != nil {
			t.Fatal(err)
		}
		if len(mod.Changes) != 1 || mod.Changes[0].Modification.Type != want {
			t.Fatalf("%s gn: sent %+v, want type %s", op, mod.Changes, want)
		}
	}
}

func TestSeedValueCheckComparesByAttributeType(t *testing.T) {
	e := ldap.NewEntry("uid=alice,ou=people,dc=example,dc=test", map[string][]string{
		"GivenName":         {"Alice"},
		"MAIL":              {"a@example.test"},
		"description;x-a":   {"tagged"},
		"givenName;lang-en": {"Alicia"},
	})
	for _, tc := range []struct {
		name, value string
		want        bool
	}{
		{"givenname", "alice", true},
		{"gn", "Alice", true},
		{"mail", "A@example.test", true},
		{"rfc822mailbox", "a@example.test", true},
		{"description", "tagged", false},
		{"description;x-a", "tagged", true},
		{"givenname", "Alicia", false},
	} {
		if got := hasAttrValue(e, tc.name, tc.value); got != tc.want {
			t.Fatalf("hasAttrValue(%s=%s) = %v, want %v", tc.name, tc.value, got, tc.want)
		}
	}
}

func TestLiveHasAttrByType(t *testing.T) {
	live := ldap.NewEntry("uid=alice,ou=people,dc=example,dc=test", map[string][]string{"givenname": {"Alice"}})
	for _, name := range []string{"gn", "givenName", "GIVENNAME"} {
		if !liveHasAttr(live, name) {
			t.Fatalf("%s must find the stored givenname", name)
		}
	}
	if liveHasAttr(live, "mail") || liveHasAttr(live, "givenName;lang-en") || liveHasAttr(nil, "gn") {
		t.Fatal("other types and option sets must not match")
	}
}

func TestUserFromEntryFoldsMailAndGivenNameAliases(t *testing.T) {
	e := ldap.NewEntry("uid=alice,ou=people,dc=example,dc=test", map[string][]string{
		"uid":                   {"alice"},
		"gn":                    {"Alice"},
		"rfc822mailbox;lang-en": {"a@example.test"},
	})
	got := map[string]string{}
	for _, kv := range userFromEntry(e, "ou=groups,dc=example,dc=test").Attributes {
		got[kv.Name] = kv.Value
	}
	if got["givenname"] != "Alice" || got["mail;lang-en"] != "a@example.test" || len(got) != 2 {
		t.Fatalf("user view attributes = %v", got)
	}
}

func TestAliasDeleteName(t *testing.T) {
	legacy := ldap.NewEntry("uid=alice,ou=people,dc=example,dc=test", map[string][]string{
		"mail":                  {"real@example.test"},
		"mail;lang-en":          {"real-en@example.test"},
		"rfc822Mailbox;lang-en": {"legacy-en@example.test"},
		"rfc822Mailbox":         {"legacy@example.test"},
	})
	primaryOnly := ldap.NewEntry("uid=alice,ou=people,dc=example,dc=test", map[string][]string{
		"mail":              {"real@example.test"},
		"mail;x-a;lang-en":  {"tagged@example.test"},
		"givenName;LANG-FR": {"Alice"},
	})
	cases := []struct {
		name string
		live *ldap.Entry
		want string
	}{
		{"rfc822Mailbox;lang-en", legacy, "rfc822Mailbox;lang-en"},     // 1: literal legacy row
		{"RFC822MAILBOX", legacy, "rfc822Mailbox"},                     // 1: stored spelling
		{"rfc822Mailbox;lang-en", primaryOnly, "mail;lang-en"},         // 2: no row, optioned
		{"rfc822Mailbox;lang-en;x-a", primaryOnly, "mail;x-a;lang-en"}, // 2: stored option order
		{"GN;lang-fr", primaryOnly, "givenName;LANG-FR"},               // 2: stored primary row
		{"GN;X-A", primaryOnly, "givenName;X-A"},                       // 2: nothing stored
		{"rfc822Mailbox", primaryOnly, "rfc822Mailbox"},                // 3: bare alias kept
		{"commonName", nil, "commonName"},                              // 3: no live entry
		{"mail;lang-en", legacy, "mail;lang-en"},                       // not an alias
		{"description", legacy, "description"},                         // not an alias
	}
	for _, tc := range cases {
		mod := ldap.NewModifyRequest("uid=alice,ou=people,dc=example,dc=test", nil)
		if err := applyEntryChange(mod, directory.EntryChange{Op: directory.EntryModDelete, Name: tc.name}, tc.live); err != nil {
			t.Fatal(err)
		}
		if got := mod.Changes[0].Modification.Type; got != tc.want {
			t.Errorf("delete %q: sent %q, want %q", tc.name, got, tc.want)
		}
	}
}
