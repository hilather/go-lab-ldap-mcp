//go:build integration

package parity

import "testing"

func TestDualEngineReviewSearchParity(t *testing.T) {
	fx := reviewFixture(t)
	native := startNative(t, fx)
	defer native.close(t)
	oracle := startOracle(t, fx)
	defer oracle.close(t)
	no := reviewSearchOutcomes(t, native)
	oo := reviewSearchOutcomes(t, oracle)
	if !outcomesEqual(no, oo) {
		t.Fatalf("C6/C8 review parity: %s", diffOutcomes("review-search", oo, no))
	}
}
