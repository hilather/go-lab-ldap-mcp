package config

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// TestFrontendAliasTableMirrorsConfig keeps the console's alias tables
// (frontend/src/lib/directory-model.ts) in step with attributeNameAliases:
// the tree page's alias guard is only as complete as that copy.
func TestFrontendAliasTableMirrorsConfig(t *testing.T) {
	src, err := os.ReadFile(filepath.Join("..", "..", "frontend", "src", "lib", "directory-model.ts"))
	if err != nil {
		t.Fatal(err)
	}
	aliases := tsRecord(t, string(src), "ATTRIBUTE_NAME_ALIASES")
	primaries := tsRecord(t, string(src), "ATTRIBUTE_PRIMARY_NAMES")
	if len(aliases) != len(attributeNameAliases) {
		t.Fatalf("frontend aliases %v, config has %d entries", aliases, len(attributeNameAliases))
	}
	for alias, a := range attributeNameAliases {
		if aliases[alias] != a.typ {
			t.Errorf("frontend alias %q -> %q, config resolves it to %q", alias, aliases[alias], a.typ)
		}
		got := a.typ
		if p, ok := primaries[a.typ]; ok {
			got = p
		}
		if got != a.primary {
			t.Errorf("frontend primary name for %q is %q, config writes %q", alias, got, a.primary)
		}
	}
	for typ, p := range primaries {
		if !strings.EqualFold(typ, p) {
			t.Errorf("frontend primary %q for type %q differs by more than case", p, typ)
		}
	}
}

// tsRecord extracts `const NAME: Record<string, string> = { key: "value", ... };`
// and fails when the block or its entries cannot be found.
func tsRecord(t *testing.T, src, name string) map[string]string {
	t.Helper()
	block := regexp.MustCompile(`(?s)const ` + name + `: Record<string, string> = \{(.*?)\n\};`).FindStringSubmatch(src)
	if block == nil {
		t.Fatalf("%s block not found in directory-model.ts", name)
	}
	out := map[string]string{}
	for _, m := range regexp.MustCompile(`(?m)^\s*"?([A-Za-z0-9.]+)"?:\s*"([^"]+)",?\s*$`).FindAllStringSubmatch(block[1], -1) {
		out[m[1]] = m[2]
	}
	if len(out) == 0 {
		t.Fatalf("%s has no parsable entries", name)
	}
	return out
}
