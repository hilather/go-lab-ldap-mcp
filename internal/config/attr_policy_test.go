package config_test

import (
	"strings"
	"testing"

	"github.com/hilather/go-lab-ldap-mcp/internal/config"
)

func TestProtectedAttrOptionsAndOIDs(t *testing.T) {
	for _, name := range []string{"userPassword;binary", "2.5.4.35", "2.5.4.35;binary", "ACI;lang-en", "2.16.840.1.113730.3.1.55", "nsAccountLock;binary"} {
		if !config.ForbiddenUserAttr(name) {
			t.Fatalf("protected write bypass via %s", name)
		}
	}
	if config.ForbiddenUserAttr("description;lang-en") {
		t.Fatal("safe option rejected")
	}
}

func TestForbiddenUserWriteAttrSingleRule(t *testing.T) {
	for _, name := range []string{
		"objectClass", "OBJECTCLASS;x-a", "2.5.4.0",
		"cn;lang-en", "commonName", "surname", "userid", "uid;x-a", "2.5.4.3", "0.9.2342.19200300.100.1.1",
		"userPassword;lang-en", "authPassword",
	} {
		if !config.ForbiddenUserWriteAttr(name) {
			t.Fatalf("%s must be rejected on user writes", name)
		}
	}
	for _, name := range []string{"cn", " CN ", "sn", "uid", "mail", "mail;lang-en", "ou", "organizationalUnitName"} {
		if config.ForbiddenUserWriteAttr(name) {
			t.Fatalf("%s must stay writable", name)
		}
	}
}

func TestCanonicalAttrTypeResolvesAliases(t *testing.T) {
	cases := map[string]string{
		"commonName;lang-en": "cn", "SURNAME": "sn", "userID": "uid", "organizationalUnitName": "ou",
		"domainComponent": "dc", "organizationName": "o", "2.5.4.0": "objectclass", "mail;x-a": "mail",
	}
	for in, want := range cases {
		if got := config.CanonicalAttrType(in); got != want {
			t.Fatalf("CanonicalAttrType(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestAttrDuplicateKey(t *testing.T) {
	same := [][2]string{{"ou", "organizationalUnitName"}, {"mail", " MAIL "}, {"ou;lang-en", "organizationalUnitName;LANG-EN"}, {"ou;lang-en;x-a", "ou;x-a;lang-en"}}
	for _, p := range same {
		if config.AttrDuplicateKey(p[0]) != config.AttrDuplicateKey(p[1]) {
			t.Fatalf("%q and %q must collide", p[0], p[1])
		}
	}
	for _, p := range [][2]string{{"mail", "rfc822Mailbox"}, {"givenName", "GN"}, {"mail;lang-en", "RFC822MAILBOX;LANG-EN"}} {
		if config.AttrDuplicateKey(p[0]) != config.AttrDuplicateKey(p[1]) {
			t.Fatalf("%q and %q must collide", p[0], p[1])
		}
	}
	diff := [][2]string{{"cn", "cn;lang-en"}, {"mail", "mail;lang-en"}, {"ou;lang-en", "ou;lang-fr"}}
	for _, p := range diff {
		if config.AttrDuplicateKey(p[0]) == config.AttrDuplicateKey(p[1]) {
			t.Fatalf("%q and %q must stay distinct", p[0], p[1])
		}
	}
}

func TestAttrAliasesForMailAndGivenName(t *testing.T) {
	for in, want := range map[string]string{"rfc822Mailbox": "mail", "GN;lang-en": "givenname", "gn": "givenname"} {
		if got := config.CanonicalAttrType(in); got != want {
			t.Fatalf("CanonicalAttrType(%q) = %q, want %q", in, got, want)
		}
	}
	for in, want := range map[string]string{
		"rfc822Mailbox;lang-en": "mail;lang-en", "GN": "givenName", " gn ": "givenName",
		"organizationalUnitName": "ou", "userid": "uid", "mail": "mail", "givenName": "givenName",
		"description;x-a": "description;x-a", "2.5.4.0": "2.5.4.0",
	} {
		if got := config.PrimaryAttrDescription(in); got != want {
			t.Fatalf("PrimaryAttrDescription(%q) = %q, want %q", in, got, want)
		}
	}
	for in, want := range map[string]string{"gn;x-a": "givenname", "RFC822Mailbox": "mail", "commonName": "cn"} {
		if got, ok := config.AttrAliasType(in); !ok || got != want {
			t.Fatalf("AttrAliasType(%q) = %q,%v, want %q", in, got, ok, want)
		}
	}
	for _, in := range []string{"mail", "givenName", "2.5.4.35", "uid"} {
		if _, ok := config.AttrAliasType(in); ok {
			t.Fatalf("AttrAliasType(%q) must be false", in)
		}
	}
	names := []string{"gn", "GN", "givenName", "rfc822Mailbox", "mail", "Mail"}
	config.SortAttrNamesForDuplicates(names)
	if got := strings.Join(names, ","); got != "givenName,GN,gn,Mail,mail,rfc822Mailbox" {
		t.Fatalf("duplicate order = %s", got)
	}
}
