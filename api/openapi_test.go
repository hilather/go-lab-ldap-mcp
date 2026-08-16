package api_test

import (
	"os"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

func TestOpenAPIContractTable(t *testing.T) {
	raw, err := os.ReadFile("openapi.yaml")
	if err != nil {
		t.Fatal(err)
	}
	text := string(raw)
	for _, leak := range []string{
		"lab-fixture-admin-token",
		"lab-fixture-alice-password",
		"lab-fixture-runtime-password",
	} {
		if strings.Contains(text, leak) {
			t.Fatalf("openapi example leaked fixture secret %q", leak)
		}
	}

	var doc struct {
		Paths map[string]yaml.Node `yaml:"paths"`
	}
	if err := yaml.Unmarshal(raw, &doc); err != nil {
		t.Fatal(err)
	}

	type op struct {
		method   string
		path     string
		proposed bool
	}
	want := []op{
		{method: "get", path: "/health"},
		{method: "get", path: "/health/ready", proposed: true},
		{method: "get", path: "/metrics"},
		{method: "get", path: "/api/v1/version", proposed: true},
		{method: "get", path: "/api/v1/capabilities", proposed: true},
		{method: "get", path: "/api/v1/baseline", proposed: true},
		{method: "post", path: "/api/v1/session"},
		{method: "get", path: "/api/v1/session", proposed: true},
		{method: "delete", path: "/api/v1/session", proposed: true},
		{method: "post", path: "/api/v1/users"},
		{method: "get", path: "/api/v1/users", proposed: true},
		{method: "get", path: "/api/v1/users/{id}", proposed: true},
		{method: "patch", path: "/api/v1/users/{id}", proposed: true},
		{method: "delete", path: "/api/v1/users/{id}", proposed: true},
		{method: "post", path: "/api/v1/users/{id}/password", proposed: true},
		{method: "post", path: "/api/v1/users/{id}/enable", proposed: true},
		{method: "post", path: "/api/v1/users/{id}/disable", proposed: true},
		{method: "get", path: "/api/v1/users/{id}/account-state", proposed: true},
		{method: "post", path: "/api/v1/users/{id}/expire-password", proposed: true},
		{method: "post", path: "/api/v1/users/{id}/clear-password-expiry", proposed: true},
		{method: "post", path: "/api/v1/users/{id}/lock", proposed: true},
		{method: "post", path: "/api/v1/users/{id}/unlock", proposed: true},
		{method: "get", path: "/api/v1/users/{id}/groups", proposed: true},
		{method: "get", path: "/api/v1/groups", proposed: true},
		{method: "post", path: "/api/v1/groups", proposed: true},
		{method: "get", path: "/api/v1/groups/{id}", proposed: true},
		{method: "delete", path: "/api/v1/groups/{id}", proposed: true},
		{method: "post", path: "/api/v1/groups/{id}/members", proposed: true},
		{method: "delete", path: "/api/v1/groups/{id}/members", proposed: true},
		{method: "put", path: "/api/v1/groups/{id}/members", proposed: true},
		{method: "post", path: "/api/v1/search", proposed: true},
		{method: "post", path: "/api/v1/auth-tests", proposed: true},
		{method: "get", path: "/api/v1/rootdse", proposed: true},
		{method: "get", path: "/api/v1/schema", proposed: true},
		{method: "get", path: "/api/v1/schema/objectclasses/{name}", proposed: true},
		{method: "get", path: "/api/v1/schema/attributes/{name}", proposed: true},
		{method: "get", path: "/api/v1/audit", proposed: true},
		{method: "post", path: "/api/v1/reset", proposed: true},
		{method: "get", path: "/api/v1/reset", proposed: true},
		{method: "get", path: "/api/v1/export", proposed: true},
		{method: "get", path: "/api/v1/diagnostics", proposed: true},
	}

	decoded := map[string]pathItem{}
	for p, node := range doc.Paths {
		var item pathItem
		if err := node.Decode(&item); err != nil {
			t.Fatalf("path %s: %v", p, err)
		}
		decoded[p] = item
	}
	if _, ok := decoded["/api/v1/groups/{id}"]["patch"]; ok {
		t.Fatal("v1 must not define PATCH /api/v1/groups/{id}")
	}
	for _, w := range want {
		item, ok := decoded[w.path]
		if !ok {
			t.Errorf("missing path %s", w.path)
			continue
		}
		rawOp, ok := item[w.method]
		if !ok {
			t.Errorf("missing %s %s", strings.ToUpper(w.method), w.path)
			continue
		}
		opm := asMap(rawOp)
		if opm == nil {
			t.Errorf("%s %s: unexpected node type %T", w.method, w.path, rawOp)
			continue
		}
		_, proposed := opm["x-labldap-contract"]
		if w.proposed && !proposed {
			t.Errorf("%s %s should be x-labldap-contract: proposed", w.method, w.path)
		}
		if !w.proposed && proposed {
			t.Errorf("%s %s is binding and must not be marked proposed", w.method, w.path)
		}
		if _, ok := opm["operationId"]; !ok {
			t.Errorf("%s %s missing operationId", w.method, w.path)
		}
	}
}

type pathItem map[string]any

func asMap(v any) map[string]any {
	switch t := v.(type) {
	case map[string]any:
		return t
	case pathItem:
		return map[string]any(t)
	default:
		return nil
	}
}
