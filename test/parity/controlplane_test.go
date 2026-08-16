package parity

import "testing"

// TestControlPlaneNative runs the control-plane Contract list against the
// in-process native engine (no Docker) and checks the expected app-level
// outcomes. Dual-engine comparison lives in TestDualEngineParity.
func TestControlPlaneNative(t *testing.T) {
	fx := compileFixture(t)
	ne := startNative(t, fx)
	// Close the engine after startControlPlane's pool Cleanup (LIFO).
	t.Cleanup(func() { ne.close(t) })
	cp := startControlPlane(t, fx, ne)

	for _, cs := range controlPlaneCases {
		cs := cs
		t.Run(cs.id+"/"+cs.name, func(t *testing.T) {
			c := *cp
			c.t = t
			got := cs.run(&c)
			want := wantControlPlane(cs.name)
			if !outcomesEqual(want, got) {
				t.Errorf("control-plane %s native outcome:\n%s",
					cs.name, diffOutcomes(cs.name, want, got))
			}
		})
	}
}
