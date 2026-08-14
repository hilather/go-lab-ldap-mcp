package directory_test

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/hilather/go-lab-ldap-mcp/internal/apperr"
	"github.com/hilather/go-lab-ldap-mcp/internal/directory"
	"github.com/hilather/go-lab-ldap-mcp/internal/observability"
)

func TestScopeSetHas(t *testing.T) {
	t.Parallel()
	s := directory.ScopeSet{"directory:read", "directory:write"}
	if !s.Has("directory:read") || s.Has("lab:reset") {
		t.Fatalf("Has mismatch: %#v", s)
	}
}

func TestPasswordSecretIsRedacted(t *testing.T) {
	t.Parallel()
	spec := directory.UserSpec{ID: "alice", Password: observability.Secret("super-secret")}
	if strings.Contains(spec.Password.String(), "super-secret") {
		t.Fatal("secret stringified")
	}
	raw, err := json.Marshal(spec)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(raw), "super-secret") {
		t.Fatalf("secret leaked in json: %s", raw)
	}
}

func TestDirectoryErrorCodes(t *testing.T) {
	t.Parallel()
	cases := []struct {
		code   string
		retry  bool
		public string
	}{
		{directory.FieldNotFound, false, "directory entry not found"},
		{directory.FieldConflict, false, "directory entry already exists"},
		{directory.FieldInvalidCredentials, false, "invalid credentials"},
		{directory.FieldConstraint, false, "directory constraint violation"},
		{directory.FieldUnavailable, true, "directory unavailable"},
		{directory.FieldForbidden, false, "directory operation not permitted"},
	}
	for _, tc := range cases {
		err := directory.Error("directory", tc.code, tc.public)
		apperr.Assert(t, err).Code(apperr.CodeDirectory).Public(tc.public).Retryable(tc.retry)
		var found bool
		for _, f := range err.Fields() {
			if f.Code == tc.code {
				found = true
			}
		}
		if !found {
			t.Fatalf("missing field code %s", tc.code)
		}
	}
}

func TestSearchQueryShape(t *testing.T) {
	t.Parallel()
	q := directory.SearchQuery{
		Base: "dc=example,dc=test", Scope: directory.SearchScopeSub,
		Filter: "(uid=alice)", PageSize: 50,
	}
	raw, err := json.Marshal(q)
	if err != nil {
		t.Fatal(err)
	}
	for _, key := range []string{`"base"`, `"scope"`, `"filter"`, `"pageSize"`} {
		if !strings.Contains(string(raw), key) {
			t.Fatalf("missing %s in %s", key, raw)
		}
	}
}

func TestCapabilitiesJSON(t *testing.T) {
	t.Parallel()
	c := directory.Capabilities{
		EngineVendor: "389 Project", Transports: []string{"ldaps"}, RequiredOK: true,
	}
	raw, err := json.Marshal(c)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(raw), `"engineVendor"`) || !strings.Contains(string(raw), `"requiredOK"`) {
		t.Fatalf("unexpected json: %s", raw)
	}
}
