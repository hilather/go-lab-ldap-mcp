package main

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
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
	crossToken = "lab-test-cross-token-value-32xxx"
	crossPass  = "unit-mcp-cross-pass-12"
)

type memUsers struct {
	mu        sync.Mutex
	byID      map[directory.UserID]directory.User
	passwords map[directory.UserID]string
}

func (m *memUsers) List(context.Context, directory.UserListQuery) (directory.UserPage, error) {
	return directory.UserPage{}, nil
}
func (m *memUsers) Get(_ context.Context, id directory.UserID) (directory.User, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	u, ok := m.byID[id]
	if !ok {
		return directory.User{}, directory.Error("entry", directory.FieldNotFound, "directory entry not found")
	}
	return u, nil
}
func (m *memUsers) Add(_ context.Context, spec directory.UserSpec) (directory.User, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.byID == nil {
		m.byID = map[directory.UserID]directory.User{}
		m.passwords = map[directory.UserID]string{}
	}
	u := directory.User{ID: spec.ID, UID: spec.ID, DN: "uid=" + spec.ID + ",ou=people,dc=example,dc=test", Enabled: true}
	u.Revision = directory.RevisionOfUser(u)
	m.byID[directory.UserID(spec.ID)] = u
	m.passwords[directory.UserID(spec.ID)] = spec.Password.Reveal()
	return u, nil
}
func (m *memUsers) Modify(context.Context, directory.UserID, directory.UserPatch, directory.Revision) (directory.User, error) {
	return directory.User{}, directory.Error("entry", directory.FieldNotFound, "unused")
}
func (m *memUsers) SetEnabled(context.Context, directory.UserID, bool, directory.Revision) (directory.User, error) {
	return directory.User{}, directory.Error("entry", directory.FieldNotFound, "unused")
}
func (m *memUsers) Delete(context.Context, directory.UserID, directory.Revision) error {
	return nil
}
func (m *memUsers) SetPassword(context.Context, directory.UserID, observability.Secret, directory.Revision) error {
	return nil
}

func TestMCPCreateVisibleOnREST(t *testing.T) {
	t.Parallel()
	users := &memUsers{}
	svc := app.New(app.Deps{Users: users, Groups: nil, Search: nil})
	reg, err := auth.NewRegistry([]auth.Token{{
		ID:     "admin",
		Scopes: []string{auth.ScopeDirectoryRead, auth.ScopeDirectoryWrite},
		Secret: observability.Secret(crossToken),
	}})
	if err != nil {
		t.Fatal(err)
	}
	rest, err := api.New(api.Options{Registry: reg, Sessions: auth.NewStore(auth.DefaultSessionConfig()), Users: svc.Users})
	if err != nil {
		t.Fatal(err)
	}
	ms, err := mcpserver.New(mcpserver.Options{
		Registry: reg, Services: svc, Flags: mcpserver.RegisterFlags{Mutations: true},
	})
	if err != nil {
		t.Fatal(err)
	}
	h := mountTransports(rest.Handler(), ms.Handler())
	ts := httptest.NewServer(h)
	t.Cleanup(ts.Close)
	client := mcp.NewClient(&mcp.Implementation{Name: "labldap-test", Version: "v0.0.1"}, nil)
	sess, err := client.Connect(t.Context(), &mcp.StreamableClientTransport{
		Endpoint:             ts.URL + mcpserver.MountPath,
		DisableStandaloneSSE: true,
		HTTPClient: &http.Client{Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
			req = req.Clone(req.Context())
			req.Header.Set("Authorization", "Bearer "+crossToken)
			return ts.Client().Transport.RoundTrip(req)
		})},
	}, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = sess.Close() })
	res, err := sess.CallTool(t.Context(), &mcp.CallToolParams{
		Name:      mcpserver.ToolCreateUser,
		Arguments: mcpserver.CreateUserInput{ID: "alice", Password: crossPass},
	})
	if err != nil || res.IsError {
		t.Fatalf("create: %+v %v", res, err)
	}

	req := httptest.NewRequest(http.MethodGet, "/api/v1/users/alice", nil)
	req.Header.Set("Authorization", "Bearer "+crossToken)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), `"id":"alice"`) {
		t.Fatalf("REST get %d %s", rec.Code, rec.Body.String())
	}
	if strings.Contains(rec.Body.String(), crossPass) {
		t.Fatal("password leaked to REST")
	}
}

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }
