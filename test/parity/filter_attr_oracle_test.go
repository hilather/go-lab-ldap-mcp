//go:build integration

package parity

import "testing"

func TestDualEngineFilterAttributeDescriptionParity(t *testing.T) {
	fx := filterAttrFixture(t)
	native := startNative(t, fx)
	defer native.close(t)
	oracle := startOracle(t, fx)
	defer oracle.close(t)
	no := filterAttrOutcomes(t, native)
	oo := filterAttrOutcomes(t, oracle)
	if !outcomesEqual(no, oo) {
		t.Fatalf("C6 filter attribute descriptions: %s", diffOutcomes("filter-attr", oo, no))
	}
}
