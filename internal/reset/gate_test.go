package reset

import (
	"testing"

	"github.com/hilather/go-lab-ldap-mcp/internal/apperr"
)

func TestGateBlocksWhenNotReady(t *testing.T) {
	t.Parallel()
	g := NewGate()
	if err := g.Allow(t.Context()); err != nil {
		t.Fatal(err)
	}
	g.Set(Resetting)
	err := g.Allow(t.Context())
	if err == nil {
		t.Fatal("reset must block writes")
	}
	apperr.Assert(t, err).Code(apperr.CodeReset).Retryable(true)
	g.Set(Ready)
	if err := g.Allow(t.Context()); err != nil {
		t.Fatal(err)
	}
}
