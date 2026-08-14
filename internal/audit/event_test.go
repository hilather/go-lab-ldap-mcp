package audit

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestMemoryHookHasNoSecrets(t *testing.T) {
	t.Parallel()
	m := &Memory{}
	m.Emit(t.Context(), Event{
		RequestID: "req-1",
		Actor:     "token:admin",
		Action:    "user.create",
		Target:    "alice",
		Result:    "success",
		Revisions: Revisions{After: "abc"},
	})
	got := m.Snapshot()
	if len(got) != 1 || got[0].RequestID != "req-1" || got[0].Revisions.After != "abc" {
		t.Fatalf("%+v", got)
	}
	raw, err := json.Marshal(got[0])
	if err != nil {
		t.Fatal(err)
	}
	low := strings.ToLower(string(raw))
	for _, n := range []string{"password", "authorization", "bearer ", "cookie"} {
		if strings.Contains(low, n) {
			t.Fatalf("secret-like field %q in %s", n, raw)
		}
	}
}
