//go:build integration

package parity

import (
	"reflect"
	"testing"
)

func TestDualEngineRebindAuthorizationParity(t *testing.T) {
	fx := reviewFixture(t)
	native := startNative(t, fx)
	defer native.close(t)
	oracle := startOracle(t, fx)
	defer oracle.close(t)
	n := rebindAuthorizationOutcomes(t, native)
	o := rebindAuthorizationOutcomes(t, oracle)
	if !reflect.DeepEqual(n, o) {
		t.Fatal("C1/C3/C8 sequential rebind authorization differs")
	}
}

// C1/C3/C8: exact ACI results with anonymous enabled. Completion order remains
// the separate ADR-0014 proposal; neither denial control grants Compare.
func TestDualEnginePipelinedAuthorizationParity(t *testing.T) {
	fx := anonymousEnabledRebindFixture(t)
	native := startNative(t, fx)
	defer native.close(t)
	oracle := startOracle(t, fx)
	defer oracle.close(t)
	n := pipelinedAuthorizationOutcomes(t, native)
	o := pipelinedAuthorizationOutcomes(t, oracle)
	if !reflect.DeepEqual(n, o) {
		t.Fatal("pipelined authorization differs")
	}
}
