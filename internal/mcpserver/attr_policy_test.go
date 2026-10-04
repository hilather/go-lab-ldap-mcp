package mcpserver

import (
	"net/http"
	"testing"

	"github.com/hilather/go-lab-ldap-mcp/internal/directory"
	"github.com/hilather/go-lab-ldap-mcp/internal/observability"
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
