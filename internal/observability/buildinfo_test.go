package observability

import (
	"encoding/json"
	"testing"
)

func TestBuildInfoJSONCamelCase(t *testing.T) {
	t.Parallel()
	b, err := json.Marshal(BuildInfo{Version: "dev", Revision: "abc", Time: "now", Component: "labldap"})
	if err != nil {
		t.Fatal(err)
	}
	var raw map[string]string
	if err := json.Unmarshal(b, &raw); err != nil {
		t.Fatal(err)
	}
	if raw["version"] != "dev" || raw["revision"] != "abc" || raw["time"] != "now" || raw["component"] != "labldap" {
		t.Fatalf("%s", b)
	}
}
