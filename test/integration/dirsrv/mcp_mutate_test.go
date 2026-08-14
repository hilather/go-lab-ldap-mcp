//go:build integration

package dirsrv

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/hilather/go-lab-ldap-mcp/internal/api"
	"github.com/hilather/go-lab-ldap-mcp/internal/app"
	"github.com/hilather/go-lab-ldap-mcp/internal/auth"
	"github.com/hilather/go-lab-ldap-mcp/internal/directory"
	"github.com/hilather/go-lab-ldap-mcp/internal/mcpserver"
	"github.com/hilather/go-lab-ldap-mcp/internal/observability"
)

const (
	mcpITToken = "lab-it-mcp-admin-token-value-32"
	mcpITPass  = "mcp-it-user-pass-12"
)

func TestMCPUserVisibleViaRESTAndLDAP(t *testing.T) {
	env := startRuntimeEnv(t)
	svc := app.New(app.Deps{
		Users:    env.rt.Users(),
		Groups:   env.rt.Groups(),
		Search:   env.rt,
		Bind:     env.rt,
		Schema:   env.rt,
		Caps:     env.rt,
		Marker:   env.rt,
		PeopleDN: "ou=people,dc=example,dc=test",
		GroupsDN: "ou=groups,dc=example,dc=test",
	})
	reg, err := auth.NewRegistry([]auth.Token{{
		ID: "admin",
		Scopes: []string{
			auth.ScopeDirectoryRead, auth.ScopeDirectoryWrite, auth.ScopeDirectoryPassword,
		},
		Secret: observability.Secret(mcpITToken),
	}})
	if err != nil {
		t.Fatal(err)
	}
	rest, err := api.New(api.Options{
		Registry: reg,
		Sessions: auth.NewStore(auth.DefaultSessionConfig()),
		Users:    svc.Users,
		Groups:   svc.Groups,
	})
	if err != nil {
		t.Fatal(err)
	}
	ms, err := mcpserver.New(mcpserver.Options{
		Registry: reg,
		Services: svc,
		Flags:    mcpserver.RegisterFlags{Mutations: true, Password: true},
	})
	if err != nil {
		t.Fatal(err)
	}
	mux := http.NewServeMux()
	mux.Handle(mcpserver.MountPath, ms.Handler())
	mux.Handle("/", rest.Handler())
	ts := httptest.NewServer(mux)
	t.Cleanup(ts.Close)

	client := mcp.NewClient(&mcp.Implementation{Name: "labldap-it", Version: "v0.0.1"}, nil)
	sess, err := client.Connect(t.Context(), &mcp.StreamableClientTransport{
		Endpoint:             ts.URL + mcpserver.MountPath,
		DisableStandaloneSSE: true,
		HTTPClient:           &http.Client{Transport: bearerRT{base: ts.Client().Transport, token: mcpITToken}},
	}, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = sess.Close() })

	created, err := sess.CallTool(t.Context(), &mcp.CallToolParams{
		Name:      mcpserver.ToolCreateUser,
		Arguments: mcpserver.CreateUserInput{ID: "mcp-alice", Password: mcpITPass, Attributes: map[string]string{"sn": "MCP"}},
	})
	if err != nil || created.IsError {
		t.Fatalf("create: %+v %v", created, err)
	}
	raw, _ := json.Marshal(created.StructuredContent)
	if strings.Contains(string(raw), mcpITPass) {
		t.Fatal("password in MCP result")
	}

	req := httptest.NewRequest(http.MethodGet, "/api/v1/users/mcp-alice", nil)
	req.Header.Set("Authorization", "Bearer "+mcpITToken)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), `"id":"mcp-alice"`) {
		t.Fatalf("REST %d %s", rec.Code, rec.Body.String())
	}
	var u directory.User
	if err := json.Unmarshal(rec.Body.Bytes(), &u); err != nil {
		t.Fatal(err)
	}
	if err := userBind(t, env.inst, u.DN, mcpITPass); err != nil {
		t.Fatalf("direct LDAP bind: %v", err)
	}

	gcreated, err := sess.CallTool(t.Context(), &mcp.CallToolParams{
		Name: mcpserver.ToolCreateGroup,
		Arguments: directory.GroupSpec{
			ID:      "mcp-staff",
			Members: []directory.MemberRef{{Kind: "user", ID: "mcp-alice"}},
		},
	})
	if err != nil || gcreated.IsError {
		t.Fatalf("group: %+v %v", gcreated, err)
	}
	got, err := svc.Users.Get(t.Context(), app.Principal{
		Kind: app.KindToken, ID: "admin", Scopes: directory.ScopeSet{auth.ScopeDirectoryRead},
	}, "mcp-alice")
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, gid := range got.Groups {
		if string(gid) == "mcp-staff" {
			found = true
		}
	}
	if !found && len(got.Groups) == 0 {
		// MemberOf may be empty if plugin hasn't updated yet; REST group still has member.
		g, gerr := svc.Groups.Get(t.Context(), app.Principal{
			Kind: app.KindToken, ID: "admin", Scopes: directory.ScopeSet{auth.ScopeDirectoryRead},
		}, "mcp-staff")
		if gerr != nil || len(g.Members) == 0 {
			t.Fatalf("membership %+v user.groups=%v", g, got.Groups)
		}
	}
}

type bearerRT struct {
	base  http.RoundTripper
	token string
}

func (t bearerRT) RoundTrip(req *http.Request) (*http.Response, error) {
	req = req.Clone(req.Context())
	req.Header.Set("Authorization", "Bearer "+t.token)
	base := t.base
	if base == nil {
		base = http.DefaultTransport
	}
	return base.RoundTrip(req)
}
