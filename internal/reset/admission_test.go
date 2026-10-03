package reset

import (
	"context"
	"errors"
	"testing"

	"github.com/hilather/go-lab-ldap-mcp/internal/directory"
)

func TestGateAbortPreservesFailedAndWaitHonorsCancellation(t *testing.T) {
	g := NewGate()
	g.MarkFailed("torn baseline")
	tok, err := g.Begin()
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if err := g.WaitIdle(ctx, tok); !errors.Is(err, context.Canceled) {
		t.Fatalf("canceled idle wait: %v", err)
	}
	g.Abort(tok)
	if g.State() != Failed || g.Snapshot().Error != "torn baseline" {
		t.Fatal("abort erased failed baseline")
	}
	if _, err := g.AcquireWrite(t.Context()); err == nil {
		t.Fatal("failed baseline admitted write")
	}
	read, err := g.AcquireRead(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	read()
}

func TestPlanIncludesAdditionalDescendantsAndPreservesRoots(t *testing.T) {
	cfg := PlanConfig{Suffix: "dc=primary", AdditionalSuffixes: []string{"dc=extra"}}
	plan := BuildPlan(directory.ManagedInventory{Extra: []string{"dc=extra", "ou=parent,dc=extra", "ou=child,ou=parent,dc=extra", "ou=foreign,dc=other"}}, cfg)
	if len(plan.Deletes) != 2 || plan.Deletes[0].DN != "ou=child,ou=parent,dc=extra" || len(plan.Extra) != 2 {
		t.Fatalf("additional suffix plan: %+v", plan)
	}
}
