package mcpserver

import (
	"net/http"
	"strings"
	"testing"

	"github.com/hilather/go-lab-ldap-mcp/internal/directory"
	"github.com/hilather/go-lab-ldap-mcp/internal/observability"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

func TestMCPWriteOnlyCannotSetPasswordThroughAttributeAliases(t *testing.T) {
	users, groups := newFakeUsers(), newFakeGroups()
	user, err := users.Add(t.Context(), directory.UserSpec{ID: "alice", Password: observability.Secret(mcpUserPass)})
	if err != nil {
		t.Fatal(err)
	}
	svc := mutationServices(users, groups, &fakeBind{})
	s := mutationServer(t, svc, nil)
	mux := http.NewServeMux()
	mux.Handle(MountPath, s.Handler())
	sess, _ := connectMCP(t, mux, writeToken, "")
	for _, attr := range []string{"userPassword;binary", "2.5.4.35", "authPassword", "objectClass", "surname", "sn;lang-en"} {
		res := callTool(t, sess, ToolUpdateUser, UpdateUserInput{ID: "alice", Revision: string(user.Revision), Attributes: map[string]string{attr: "replacement"}})
		if !res.IsError {
			t.Fatalf("alias %s bypass", attr)
		}
	}
}

func TestMCPMailAndGivenNameAliasesAreDuplicates(t *testing.T) {
	users, groups := newFakeUsers(), newFakeGroups()
	user, err := users.Add(t.Context(), directory.UserSpec{ID: "alice", Password: observability.Secret(mcpUserPass)})
	if err != nil {
		t.Fatal(err)
	}
	svc := mutationServices(users, groups, &fakeBind{})
	s := mutationServer(t, svc, nil)
	mux := http.NewServeMux()
	mux.Handle(MountPath, s.Handler())
	sess, _ := connectMCP(t, mux, writeToken, "")
	for _, tc := range []struct {
		attrs map[string]string
		field string
	}{
		{map[string]string{"mail": "a@example.test", "rfc822Mailbox": "b@example.test"}, "attributes.rfc822Mailbox"},
		{map[string]string{"givenName": "A", "gn": "B"}, "attributes.gn"},
		{map[string]string{"GN": "A", "givenName": "B"}, "attributes.givenName"},
	} {
		upd := callTool(t, sess, ToolUpdateUser, UpdateUserInput{ID: "alice", Revision: string(user.Revision), Attributes: tc.attrs})
		crt := callTool(t, sess, ToolCreateUser, CreateUserInput{ID: "bob", Password: mcpUserPass, Attributes: tc.attrs})
		for name, res := range map[string]*mcp.CallToolResult{"update": upd, "create": crt} {
			// MCP tool errors carry the structured code, not the field path
			// (REST pins the path for the same validateAttrMap rule).
			text := toolErrText(res)
			if !res.IsError || !strings.Contains(text, "(duplicate_attribute)") {
				t.Fatalf("%s %v: want duplicate_attribute (%s), got error=%v %s", name, tc.attrs, tc.field, res.IsError, text)
			}
		}
	}
}
