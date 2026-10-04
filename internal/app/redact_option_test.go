package app

import (
	"testing"

	"github.com/hilather/go-lab-ldap-mcp/internal/directory"
)

func TestRedactAttrsDropsEveryPasswordSpelling(t *testing.T) {
	in := []directory.AttrKV{
		{Name: "userPassword;lang-en", Value: "canary-1"},
		{Name: "USERPASSWORD;x;y", Value: "canary-2"},
		{Name: "2.5.4.35", Value: "canary-3"},
		{Name: "cn;lang-en", Value: "Alice"},
	}
	out := redactAttrs(in)
	if len(out) != 1 || out[0].Name != "cn;lang-en" {
		t.Fatalf("redacted = %#v", out)
	}
	if !secretSchemaAttr("userPassword;binary") {
		t.Fatal("schema redaction must match optioned userPassword")
	}
}
