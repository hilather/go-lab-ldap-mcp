package directory_test

import (
	"testing"

	"github.com/hilather/go-lab-ldap-mcp/internal/directory"
)

func TestForbiddenEntryAndSecretAttrMatchAttributeType(t *testing.T) {
	for _, name := range []string{"userPassword;x", "aci;x", "nsslapd-rootpw;x", "2.5.4.35"} {
		if !directory.ForbiddenEntryAttr(name) {
			t.Fatalf("entry write %q must be forbidden", name)
		}
	}
	for _, name := range []string{"userPassword;lang-en", "authPassword;x", "2.5.4.35"} {
		if !directory.SecretAttr(name) {
			t.Fatalf("%q must be treated as secret", name)
		}
	}
	if directory.ForbiddenEntryAttr("description;lang-en") || directory.SecretAttr("cn;lang-en") {
		t.Fatal("ordinary optioned attributes must stay allowed")
	}
}
