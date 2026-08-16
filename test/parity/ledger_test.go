package parity

import (
	"os"
	"strings"
	"testing"
)

// TestDeltaLedgerSchema validates the committed delta ledger without any
// engine: every logged candidate has both outcome columns, a known
// verdict, and the CAND id set is complete. This runs hermetically so the
// ledger T-150 consumes can never be structurally broken on a machine
// without Docker.
func TestDeltaLedgerSchema(t *testing.T) {
	l := loadLedger(t)
	if l.Version != ledgerVersion {
		t.Fatalf("ledger version %q, want %q", l.Version, ledgerVersion)
	}
	if l.Oracle == "" {
		t.Fatal("ledger missing oracle provenance")
	}

	wantIDs := map[string]bool{}
	for _, p := range candProbes {
		wantIDs[p.id] = true
	}
	seen := map[string]bool{}
	for _, c := range l.Candidates {
		if !wantIDs[c.ID] {
			t.Errorf("ledger candidate %s is not a known CAND id", c.ID)
		}
		if seen[c.ID] {
			t.Errorf("ledger candidate %s duplicated", c.ID)
		}
		seen[c.ID] = true
		switch c.Verdict {
		case "match", "delta":
		default:
			t.Errorf("candidate %s: unknown verdict %q", c.ID, c.Verdict)
		}
		if len(c.Oracle) == 0 || len(c.Native) == 0 {
			t.Errorf("candidate %s: empty oracle/native outcome column", c.ID)
		}
		if len(c.Oracle) != len(c.Native) {
			t.Errorf("candidate %s: oracle/native step counts differ (%d vs %d)", c.ID, len(c.Oracle), len(c.Native))
		}
		if c.Topic == "" {
			t.Errorf("candidate %s: missing topic", c.ID)
		}
	}
	for id := range wantIDs {
		if !seen[id] {
			t.Errorf("ledger is missing candidate %s", id)
		}
	}

	// Contract entries must be non-empty and uniquely keyed.
	seenCase := map[string]bool{}
	for _, c := range l.Contract {
		key := c.ID + "/" + c.Name
		if seenCase[key] {
			t.Errorf("ledger contract case %s duplicated", key)
		}
		seenCase[key] = true
		if len(c.Agreed) == 0 {
			t.Errorf("ledger contract case %s has no outcomes", key)
		}
	}
	if len(seenCase) != len(contractCases) {
		t.Errorf("ledger covers %d contract cases, suite defines %d", len(seenCase), len(contractCases))
	}

	// The ledger must never carry secret material.
	raw, err := os.ReadFile(ledgerPath())
	if err != nil {
		t.Fatalf("parity: read raw ledger: %v", err)
	}
	secrets := []string{runtimePassword, nativeDMSecret}
	for _, pw := range userPasswords {
		secrets = append(secrets, pw)
	}
	for _, s := range secrets {
		if strings.Contains(string(raw), s) {
			t.Errorf("ledger contains a secret value (%q...)", s[:12])
		}
	}
}
