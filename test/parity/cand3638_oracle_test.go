//go:build integration

package parity

import "testing"

func TestDualEngineCand3638Parity(t *testing.T) {
	fx := c38Fixture(t)
	native := startNative(t, fx)
	defer native.close(t)
	oracle := startOracle(t, fx)
	defer oracle.close(t)
	no := c38Outcomes(t, native)
	oo := c38Outcomes(t, oracle)
	if !outcomesEqual(no, oo) {
		t.Fatalf("C8 CAND-36/37/38 parity: %s", diffOutcomes("cand3638", oo, no))
	}
}
