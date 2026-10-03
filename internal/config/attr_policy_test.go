package config_test

import (
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
