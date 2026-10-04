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

func TestRESTMailAndGivenNameAliasesAreDuplicates(t *testing.T) {
	s, users, _ := directoryServer(t)
	user, err := users.Add(t.Context(), directory.UserSpec{ID: "alice", Password: observability.Secret(userPass)})
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		attrs map[string]string
		field string
	}{
		{map[string]string{"mail": "a@example.test", "rfc822Mailbox": "b@example.test"}, "attributes.rfc822Mailbox"},
		{map[string]string{"givenName": "A", "gn": "B"}, "attributes.gn"},
		{map[string]string{"givenName": "A", "GN": "B"}, "attributes.GN"},
	} {
		for _, method := range []string{http.MethodPost, http.MethodPatch} {
			payload := map[string]any{"attributes": tc.attrs}
			path := "/api/v1/users/alice"
			if method == http.MethodPost {
				payload["id"] = "bob"
				payload["password"] = userPass
				path = "/api/v1/users"
			}
			body, _ := json.Marshal(payload)
			req := httptest.NewRequest(method, path, strings.NewReader(string(body)))
			req.Header.Set("Authorization", "Bearer "+writeOnlyToken)
			req.Header.Set("Content-Type", "application/json")
			if method == http.MethodPatch {
				req.Header.Set("If-Match", `"`+string(user.Revision)+`"`)
			}
			rr := httptest.NewRecorder()
			s.Handler().ServeHTTP(rr, req)
			if rr.Code != http.StatusBadRequest {
				t.Fatalf("%s %v: status %d body %s", method, tc.attrs, rr.Code, rr.Body.String())
			}
			out := rr.Body.String()
			if !strings.Contains(out, "duplicate_attribute") || !strings.Contains(out, `"`+tc.field+`"`) {
				t.Fatalf("%s %v: want duplicate_attribute at %s, body %s", method, tc.attrs, tc.field, out)
			}
		}
	}
}
