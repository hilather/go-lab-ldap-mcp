package ldapclient

import (
	"testing"

	"github.com/hilather/go-lab-ldap-mcp/internal/directory"
)

func TestPoolDoesNotReplayAmbiguousMutation(t *testing.T) {
	p, err := NewPool(testPoolCfg(fakeDial, 1))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = p.Close() })
	calls := 0
	err = p.Do(t.Context(), func(*Conn) error {
		calls++
		return directory.Error("connection", directory.FieldUnavailable, "response lost after commit")
	})
	if err == nil || calls != 1 {
		t.Fatalf("ambiguous callback replay: calls=%d err=%v", calls, err)
	}
	if p.Stats().Active != 0 || p.Stats().Idle != 0 {
		t.Fatal("broken connection retained")
	}
	if err := p.Do(t.Context(), func(*Conn) error { return nil }); err != nil {
		t.Fatal(err)
	}
}
