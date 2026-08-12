package config_test

import (
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"testing"

	"github.com/hilather/go-lab-ldap-mcp/internal/config/v1alpha1"
)

func TestSchemaEnumsMatchGo(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join("..", "..", "config", "schema", "v1alpha1.json"))
	if err != nil {
		t.Fatal(err)
	}
	var schema map[string]any
	if err := json.Unmarshal(raw, &schema); err != nil {
		t.Fatal(err)
	}
	if schema["$schema"] != "https://json-schema.org/draft/2020-12/schema" {
		t.Fatalf("dialect = %v", schema["$schema"])
	}

	defs := schema["$defs"].(map[string]any)
	checks := []struct {
		got  []string
		path []string
	}{
		{v1alpha1.APIVersions(), []string{"properties", "apiVersion", "enum"}},
		{v1alpha1.Kinds(), []string{"properties", "kind", "enum"}},
		{v1alpha1.StorageModes(), []string{"$defs", "lifecycle", "properties", "storageMode", "enum"}},
		{v1alpha1.StartupModes(), []string{"$defs", "lifecycle", "properties", "startupMode", "enum"}},
		{v1alpha1.TLSModes(), []string{"$defs", "management", "properties", "tls", "properties", "mode", "enum"}},
		{v1alpha1.Scopes(), []string{"$defs", "token", "properties", "scopes", "items", "enum"}},
		{v1alpha1.PrincipalKinds(), []string{"$defs", "acl", "properties", "principal", "properties", "kind", "enum"}},
		{v1alpha1.TargetKinds(), []string{"$defs", "acl", "properties", "target", "properties", "kind", "enum"}},
		{v1alpha1.Permissions(), []string{"$defs", "acl", "properties", "permissions", "items", "enum"}},
		{v1alpha1.StorageSchemes(), []string{"$defs", "passwordPolicy", "properties", "storageScheme", "enum"}},
		{v1alpha1.SearchScopes(), []string{"$defs", "searchScope", "enum"}},
	}
	_ = defs
	for _, c := range checks {
		got := walkEnum(schema, c.path)
		want := append([]string(nil), c.got...)
		sort.Strings(got)
		sort.Strings(want)
		if !reflect.DeepEqual(got, want) {
			t.Errorf("enum %v\n got %v\nwant %v", c.path, got, want)
		}
	}
}

func walkEnum(root any, path []string) []string {
	cur := root
	for _, p := range path {
		m, ok := cur.(map[string]any)
		if !ok {
			return nil
		}
		cur = m[p]
	}
	arr, ok := cur.([]any)
	if !ok {
		return nil
	}
	out := make([]string, 0, len(arr))
	for _, v := range arr {
		s, _ := v.(string)
		out = append(out, s)
	}
	return out
}
