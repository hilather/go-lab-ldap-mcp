package audit

import (
	"encoding/json"
	"strings"
	"testing"
	"time"
)

func TestMemoryHookHasNoSecrets(t *testing.T) {
	t.Parallel()
	m := &Memory{}
	m.Emit(t.Context(), Event{
		RequestID: "req-1",
		Actor:     "token:admin",
		Action:    ActionUserCreate,
		Target:    "alice",
		Result:    ResultSuccess,
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

func TestTaxonomyCoversDesignActions(t *testing.T) {
	t.Parallel()
	want := []string{
		ActionAuthenticate, ActionSessionCreate, ActionSessionDestroy,
		ActionUserCreate, ActionUserUpdate, ActionUserDelete, ActionUserSetEnabled, ActionUserSetPassword,
		ActionGroupCreate, ActionGroupDelete, ActionGroupMembers,
		ActionBindTest, ActionReset, ActionExport, ActionAuthzDeny,
	}
	have := map[string]bool{}
	for _, a := range KnownActions() {
		have[a] = true
	}
	for _, a := range want {
		if !have[a] {
			t.Fatalf("missing action %q", a)
		}
	}
}

func TestEventJSONMatchesContract(t *testing.T) {
	t.Parallel()
	ev := Event{
		Time:      time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC),
		RequestID: "req-9",
		Actor:     "session:abc",
		Action:    ActionBindTest,
		Target:    "bind",
		Result:    "invalid_credentials",
		Revisions: Revisions{Before: "a", After: "b"},
	}
	raw, err := json.Marshal(ev)
	if err != nil {
		t.Fatal(err)
	}
	var m map[string]any
	if err := json.Unmarshal(raw, &m); err != nil {
		t.Fatal(err)
	}
	for _, k := range []string{"time", "action", "actor", "target", "result", "requestId", "revisions"} {
		if _, ok := m[k]; !ok {
			t.Fatalf("missing %s in %s", k, raw)
		}
	}
	if strings.Contains(string(raw), "password") || strings.Contains(string(raw), "Bearer") {
		t.Fatalf("secret-like content: %s", raw)
	}
}

func TestActorIsNonSecretIdentifier(t *testing.T) {
	t.Parallel()
	for _, actor := range []string{"token:admin", "session:deadbeef"} {
		ev := Event{Actor: actor, Action: ActionAuthenticate, Result: ResultSuccess}
		raw, _ := json.Marshal(ev)
		if strings.Contains(string(raw), "lab-test") || strings.Contains(strings.ToLower(string(raw)), "bearer") {
			t.Fatalf("%s", raw)
		}
	}
}
