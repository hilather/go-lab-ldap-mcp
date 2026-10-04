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
