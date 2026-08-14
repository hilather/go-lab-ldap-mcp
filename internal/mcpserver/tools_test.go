package mcpserver

import (
	"encoding/json"
	"net/http"
	"strings"
	"testing"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/hilather/go-lab-ldap-mcp/internal/app"
	"github.com/hilather/go-lab-ldap-mcp/internal/directory"
)

func TestReadOnlyTokenCanCallReadTools(t *testing.T) {
	t.Parallel()
	search := &fakeSearch{pages: []directory.SearchPage{{
		Entries: []directory.SearchEntry{{
			DN: "uid=alice,ou=people,dc=example,dc=test",
			Attributes: []directory.AttrKV{
				{Name: "uid", Value: "alice"},
				{Name: "userPassword", Value: "unit-mcp-search-pass-12"},
			},
		}},
		NextCursor: "cursor-2",
	}}}
	svc := testServices(search, fakeCaps{caps: directory.Capabilities{
		EngineVendor: "389 Project", EngineVersion: "2.4.6", AdapterVersion: "ds389",
		Transports: []string{"ldaps"}, Plugins: []string{"memberOf"}, PasswordScheme: "PBKDF2-SHA512",
		Controls: []string{directory.ControlAssertionOID}, RequiredOK: true,
	}}, fakeMarker{m: directory.BaselineMarker{AppliedRevision: "aaa", DN: "cn=labldap-baseline,dc=example,dc=test"}}, fakeSchema{
		dse: directory.RootDSE{VendorName: "389 Project"},
		sch: directory.Schema{
			ObjectClasses: []directory.ObjectClass{{Name: "inetOrgPerson"}},
			Attributes:    []directory.AttributeType{{Name: "uid"}},
		},
	})
	s := testServer(t, svc)
	mux := http.NewServeMux()
	mux.Handle(MountPath, s.Handler())
	sess, _ := connectMCP(t, mux, readToken, "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb")

	caps, err := sess.CallTool(t.Context(), &mcp.CallToolParams{Name: ToolCapabilities})
	if err != nil || caps.IsError {
		t.Fatalf("capabilities: %+v %v", caps, err)
	}
	gotCaps := decodeStructured[directory.Capabilities](t, caps)
	if gotCaps.EngineVendor != "389 Project" || !gotCaps.RequiredOK {
		t.Fatalf("caps = %+v", gotCaps)
	}

	base, err := sess.CallTool(t.Context(), &mcp.CallToolParams{Name: ToolBaseline})
	if err != nil || base.IsError {
		t.Fatalf("baseline: %+v %v", base, err)
	}
	gotBase := decodeStructured[app.Baseline](t, base)
	if gotBase.ExpectedRevision != "aaa" || gotBase.ControlRevision != "bbb" || !gotBase.Match {
		t.Fatalf("baseline = %+v", gotBase)
	}

	page, err := sess.CallTool(t.Context(), &mcp.CallToolParams{
		Name: ToolSearch,
		Arguments: directory.SearchQuery{
			Filter: "(uid=alice)", PageSize: 1, Scope: directory.SearchScopeSub,
		},
	})
	if err != nil || page.IsError {
		t.Fatalf("search: %+v %v", page, err)
	}
	gotPage := decodeStructured[directory.SearchPage](t, page)
	if len(gotPage.Entries) != 1 || gotPage.NextCursor != "cursor-2" {
		t.Fatalf("search page = %+v", gotPage)
	}
	for _, a := range gotPage.Entries[0].Attributes {
		if strings.EqualFold(a.Name, "userPassword") || a.Value == "unit-mcp-search-pass-12" {
			t.Fatalf("password leaked in search: %+v", gotPage)
		}
	}

	entry, err := sess.CallTool(t.Context(), &mcp.CallToolParams{
		Name:      ToolGetEntry,
		Arguments: GetEntryInput{DN: "uid=alice,ou=people,dc=example,dc=test"},
	})
	if err != nil || entry.IsError {
		t.Fatalf("get-entry: %+v %v", entry, err)
	}

	search.mu.Lock()
	if len(search.calls) < 2 {
		t.Fatalf("expected search + get-entry, got %+v", search.calls)
	}
	first := search.calls[0]
	if first.Filter != "(uid=alice)" || first.PageSize != 1 {
		t.Fatalf("search query not forwarded: %+v", first)
	}
	second := search.calls[1]
	if second.Base != "uid=alice,ou=people,dc=example,dc=test" || second.Scope != directory.SearchScopeBase {
		t.Fatalf("get-entry query: %+v", second)
	}
	search.mu.Unlock()
}

func TestSearchPagingMatchesApp(t *testing.T) {
	t.Parallel()
	search := &fakeSearch{pages: []directory.SearchPage{
		{Entries: []directory.SearchEntry{{DN: "uid=a,dc=x", Attributes: []directory.AttrKV{{Name: "uid", Value: "a"}}}}, NextCursor: "page-2"},
		{Entries: []directory.SearchEntry{{DN: "uid=b,dc=x", Attributes: []directory.AttrKV{{Name: "uid", Value: "b"}}}}, NextCursor: ""},
	}}
	s := testServer(t, testServices(search, fakeCaps{}, fakeMarker{}, fakeSchema{}))
	mux := http.NewServeMux()
	mux.Handle(MountPath, s.Handler())
	sess, _ := connectMCP(t, mux, readToken, "")

	first, err := sess.CallTool(t.Context(), &mcp.CallToolParams{
		Name:      ToolSearch,
		Arguments: directory.SearchQuery{Filter: "(uid=*)", PageSize: 1},
	})
	if err != nil || first.IsError {
		t.Fatalf("page1: %+v %v", first, err)
	}
	p1 := decodeStructured[directory.SearchPage](t, first)
	if p1.NextCursor != "page-2" || len(p1.Entries) != 1 {
		t.Fatalf("page1 = %+v", p1)
	}
	second, err := sess.CallTool(t.Context(), &mcp.CallToolParams{
		Name:      ToolSearch,
		Arguments: directory.SearchQuery{Filter: "(uid=*)", PageSize: 1, Cursor: p1.NextCursor},
	})
	if err != nil || second.IsError {
		t.Fatalf("page2: %+v %v", second, err)
	}
	p2 := decodeStructured[directory.SearchPage](t, second)
	if p2.NextCursor != "" || len(p2.Entries) != 1 || p2.Entries[0].DN != "uid=b,dc=x" {
		t.Fatalf("page2 = %+v", p2)
	}
	search.mu.Lock()
	defer search.mu.Unlock()
	if len(search.calls) != 2 || search.calls[1].Cursor != "page-2" || search.calls[1].PageSize != 1 {
		t.Fatalf("app queries = %+v", search.calls)
	}
}

func TestReadResourcesEnforceScopes(t *testing.T) {
	t.Parallel()
	search := &fakeSearch{pages: []directory.SearchPage{{
		Entries: []directory.SearchEntry{{DN: "uid=alice,dc=x", Attributes: []directory.AttrKV{{Name: "uid", Value: "alice"}}}},
	}}}
	svc := testServices(search, fakeCaps{caps: directory.Capabilities{EngineVendor: "389 Project"}}, fakeMarker{m: directory.BaselineMarker{AppliedRevision: "aaa"}}, fakeSchema{
		dse: directory.RootDSE{VendorName: "389 Project"},
		sch: directory.Schema{
			ObjectClasses: []directory.ObjectClass{{Name: "inetOrgPerson", Kind: "structural"}},
			Attributes:    []directory.AttributeType{{Name: "uid", Syntax: "1.3.6.1.4.1.1466.115.121.1.15"}},
		},
	})
	s := testServer(t, svc)
	mux := http.NewServeMux()
	mux.Handle(MountPath, s.Handler())
	reader, _ := connectMCP(t, mux, readToken, "")

	for _, uri := range []string{resourceCapabilities, resourceBaseline, "labldap://entry?dn=uid%3Dalice%2Cdc%3Dx"} {
		res, err := reader.ReadResource(t.Context(), &mcp.ReadResourceParams{URI: uri})
		if err != nil {
			t.Fatalf("read %s: %v", uri, err)
		}
		if len(res.Contents) != 1 || res.Contents[0].Text == "" {
			t.Fatalf("%s empty: %+v", uri, res)
		}
		if strings.Contains(res.Contents[0].Text, "unit-mcp") {
			t.Fatalf("%s leaked secret", uri)
		}
	}

	_, err := reader.ReadResource(t.Context(), &mcp.ReadResourceParams{URI: resourceRootDSE})
	if err == nil {
		t.Fatal("reader must not read rootdse without schema:read")
	}

	schemaSess, _ := connectMCP(t, mux, schemaTok, "")
	dse, err := schemaSess.ReadResource(t.Context(), &mcp.ReadResourceParams{URI: resourceRootDSE})
	if err != nil || len(dse.Contents) == 0 {
		t.Fatalf("schema rootdse: %v %+v", err, dse)
	}
	oc, err := schemaSess.ReadResource(t.Context(), &mcp.ReadResourceParams{URI: "labldap://schema/objectclass/inetOrgPerson"})
	if err != nil {
		t.Fatal(err)
	}
	var parsed directory.ObjectClass
	if err := json.Unmarshal([]byte(oc.Contents[0].Text), &parsed); err != nil || !strings.EqualFold(parsed.Name, "inetOrgPerson") {
		t.Fatalf("objectclass = %s", oc.Contents[0].Text)
	}
}

func TestMissingReadScopeDenied(t *testing.T) {
	t.Parallel()
	s := testServer(t, testServices(&fakeSearch{}, fakeCaps{caps: directory.Capabilities{EngineVendor: "x"}}, fakeMarker{}, fakeSchema{}))
	mux := http.NewServeMux()
	mux.Handle(MountPath, s.Handler())
	sess, _ := connectMCP(t, mux, schemaTok, "")
	res, err := sess.CallTool(t.Context(), &mcp.CallToolParams{Name: ToolCapabilities})
	if err != nil {
		t.Fatal(err)
	}
	if !res.IsError {
		t.Fatalf("schema token must not call capabilities: %+v", res)
	}
	text := ""
	if len(res.Content) > 0 {
		if tc, ok := res.Content[0].(*mcp.TextContent); ok {
			text = tc.Text
		}
	}
	if strings.Contains(text, "schema") && strings.Contains(text, "admin") {
		t.Fatalf("leaked token id: %s", text)
	}
}

func TestMutationsRegisterOnlyWhenEnabled(t *testing.T) {
	t.Parallel()
	flags := RegisterFlags{Mutations: true, Password: true}
	s, err := New(Options{
		Registry: testRegistry(t),
		Services: testServices(&fakeSearch{}, fakeCaps{}, fakeMarker{}, fakeSchema{}),
		Flags:    flags,
	})
	if err != nil {
		t.Fatal(err)
	}
	mux := http.NewServeMux()
	mux.Handle(MountPath, s.Handler())
	sess, _ := connectMCP(t, mux, testToken, "")
	var names []string
	for tool, err := range sess.Tools(t.Context(), nil) {
		if err != nil {
			t.Fatal(err)
		}
		names = append(names, tool.Name)
		if tool.Name == ToolDeleteUser || tool.Name == ToolDeleteGroup {
			if tool.Annotations == nil || tool.Annotations.DestructiveHint == nil || !*tool.Annotations.DestructiveHint {
				t.Fatalf("%s missing destructive hint", tool.Name)
			}
		}
		if tool.Name == ToolResetSuffix || tool.Name == ToolExportLDIF {
			t.Fatalf("T-092 tool registered before handlers: %s", tool.Name)
		}
	}
	want := registeredTools(flags)
	if !equalSet(names, want) {
		t.Fatalf("tools = %v want %v", names, want)
	}
}
