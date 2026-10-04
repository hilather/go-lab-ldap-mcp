package config_test

import (
	"testing"

	"github.com/hilather/go-lab-ldap-mcp/internal/config"
)

func TestForbiddenUserAttrMatchesAttributeType(t *testing.T) {
	for _, name := range []string{"userPassword;lang-en", "USERPASSWORD;x;y", " userpassword;x ", "aci;x", "nsAccountLock;x", "modifyTimestamp;x", "memberOf;x"} {
		if !config.ForbiddenUserAttr(name) {
			t.Fatalf("%q must be forbidden", name)
		}
	}
	for _, name := range []string{"cn;lang-en", "description;lang-en", "mail"} {
		if config.ForbiddenUserAttr(name) {
			t.Fatalf("%q must stay allowed", name)
		}
	}
	// CanonicalAttr stays the option-preserving map key.
	if got := config.CanonicalAttr(" CN;Lang-EN "); got != "cn;lang-en" {
		t.Fatalf("CanonicalAttr = %q", got)
	}
	if got := config.CanonicalAttrType(" CN;Lang-EN "); got != "cn" {
		t.Fatalf("CanonicalAttrType = %q", got)
	}
}
