package parity

import "testing"

// runContract executes every Contract case against one engine, in the
// fixed table order, and returns the per-case outcome sequences.
func runContract(t *testing.T, fx *fixture, e engine) []ledgerCaseEntry {
	t.Helper()
	out := make([]ledgerCaseEntry, 0, len(contractCases))
	for _, cs := range contractCases {
		cs := cs
		t.Run(e.name()+"/"+cs.id+"/"+cs.name, func(t *testing.T) {
			c := &caseCtx{t: t, fx: fx, e: e}
			out = append(out, ledgerCaseEntry{ID: cs.id, Name: cs.name, Agreed: cs.run(c)})
		})
	}
	return out
}

// runCandidates executes every CAND probe against one engine, in id
// order, returning outcomes keyed by candidate id.
func runCandidates(t *testing.T, fx *fixture, e engine) map[string][]opOutcome {
	t.Helper()
	out := make(map[string][]opOutcome, len(candProbes))
	for _, p := range candProbes {
		p := p
		t.Run(e.name()+"/"+p.id, func(t *testing.T) {
			c := &caseCtx{t: t, fx: fx, e: e}
			out[p.id] = p.run(c)
		})
	}
	return out
}
