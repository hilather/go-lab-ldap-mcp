package mcpserver

import (
	"strings"
	"testing"

	"github.com/hilather/go-lab-ldap-mcp/internal/auth"
)

func TestCatalogUniqueAndComplete(t *testing.T) {
	t.Parallel()
	if err := ValidateCatalog(); err != nil {
		t.Fatal(err)
	}
	d, ok := LookupTool(ToolSearch)
	if !ok || d.Contract != ContractBinding || d.Scope != auth.ScopeDirectoryRead || !d.ReadOnly {
		t.Fatalf("binding search: %+v", d)
	}
	want := []string{
		ToolSearch, ToolCapabilities, ToolBaseline, ToolGetEntry,
		ToolCreateUser, ToolUpdateUser, ToolDeleteUser, ToolSetPassword,
		ToolCreateGroup, ToolDeleteGroup, ToolAddMembers, ToolRemoveMembers, ToolReplaceMembers,
		ToolBindTest, ToolResetSuffix, ToolExportLDIF,
	}
	got := Catalog()
	if len(got) != len(want) {
		t.Fatalf("catalog len %d want %d", len(got), len(want))
	}
	for i, name := range want {
		if got[i].Name != name {
			t.Errorf("catalog[%d] = %s want %s", i, got[i].Name, name)
		}
		if got[i].Description == "" || got[i].Scope == "" {
			t.Errorf("%s missing description or scope", name)
		}
	}
}

func TestCatalogMarkdownLockNote(t *testing.T) {
	t.Parallel()
	md := CatalogMarkdown()
	for _, name := range []string{ToolSearch, ToolCapabilities, ToolGetEntry, ToolCreateUser, resourceCapabilities, templateEntry} {
		if !strings.Contains(md, name) {
			t.Errorf("docs generator missing %s", name)
		}
	}
	if !strings.Contains(md, "binding") || !strings.Contains(md, "proposed") {
		t.Fatal(md)
	}
}

func TestRedactSensitiveInputs(t *testing.T) {
	t.Parallel()
	const secret = "unit-mcp-password-value-12"
	out := RedactArgs(ToolCreateUser, map[string]any{"id": "alice", "password": secret})
	if out["id"] != "alice" || out["password"] != "[redacted]" {
		t.Fatalf("%+v", out)
	}
	if strings.Contains(strings.Join(stringVals(out), " "), secret) {
		t.Fatal("password leaked")
	}
	bind := RedactArgs(ToolBindTest, map[string]any{"identity": "alice", "password": secret})
	if bind["password"] != "[redacted]" {
		t.Fatalf("bind-test: %+v", bind)
	}
	search := RedactArgs(ToolSearch, map[string]any{"filter": "(uid=alice)"})
	if search["filter"] != "(uid=alice)" {
		t.Fatalf("search over-redacted: %+v", search)
	}
}

func TestShouldRegisterFlags(t *testing.T) {
	t.Parallel()
	search, _ := LookupTool(ToolSearch)
	create, _ := LookupTool(ToolCreateUser)
	pw, _ := LookupTool(ToolSetPassword)
	reset, _ := LookupTool(ToolResetSuffix)
	off := RegisterFlags{}
	if !search.ShouldRegister(off) || create.ShouldRegister(off) || pw.ShouldRegister(off) || reset.ShouldRegister(off) {
		t.Fatal("read tools only when flags are off")
	}
	on := RegisterFlags{Mutations: true, Password: true, Reset: true, Export: true}
	if !create.ShouldRegister(on) || !pw.ShouldRegister(on) || !reset.ShouldRegister(on) {
		t.Fatal("enabled flags must register mutation catalog rows")
	}
}

func stringVals(m map[string]any) []string {
	var out []string
	for _, v := range m {
		if s, ok := v.(string); ok {
			out = append(out, s)
		}
	}
	return out
}
