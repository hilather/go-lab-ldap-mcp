package api

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/hilather/go-lab-ldap-mcp/internal/directory"
	"github.com/hilather/go-lab-ldap-mcp/internal/observability"
)

func TestRESTWriteOnlyCannotSetPasswordThroughAttributeAliases(t *testing.T) {
	s, users, _ := directoryServer(t)
	user, err := users.Add(t.Context(), directory.UserSpec{ID: "alice", Password: observability.Secret(userPass)})
	if err != nil {
		t.Fatal(err)
	}
	for _, attr := range []string{"userPassword;binary", "2.5.4.35", "authPassword", "nsAccountLock;binary", "objectClass", "commonName", "cn;lang-en", "userid"} {
		body, _ := json.Marshal(map[string]any{"attributes": map[string]string{attr: "replacement"}})
		req := httptest.NewRequest(http.MethodPatch, "/api/v1/users/alice", strings.NewReader(string(body)))
		req.Header.Set("Authorization", "Bearer "+writeOnlyToken)
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("If-Match", `"`+string(user.Revision)+`"`)
		rr := httptest.NewRecorder()
		s.Handler().ServeHTTP(rr, req)
		if rr.Code != http.StatusBadRequest {
			t.Fatalf("alias %s bypass: status %d", attr, rr.Code)
		}
	}
}
